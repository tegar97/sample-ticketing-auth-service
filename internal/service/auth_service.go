package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	jwtSecret   string
}

func NewAuthService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository, jwtSecret string) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtSecret:   jwtSecret,
	}
}

func (s *AuthService) Register(req *models.RegisterRequest, ipAddress, userAgent string) (*models.User, error) {
	existingUser, _ := s.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		// Log failed registration attempt
		s.logActivity("", "", models.ActivityRegister, ipAddress, userAgent,
			fmt.Sprintf("Registration failed: email %s already exists", req.Email), false)
		return nil, errors.New("email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:    req.Email,
		Password: string(hashedPassword),
		Name:     req.Name,
	}

	err = s.userRepo.Create(user)
	if err != nil {
		// Log failed registration attempt
		s.logActivity("", "", models.ActivityRegister, ipAddress, userAgent,
			fmt.Sprintf("Registration failed: database error for %s", req.Email), false)
		return nil, err
	}

	// Log successful registration
	s.logActivity(user.ID, "", models.ActivityRegister, ipAddress, userAgent,
		fmt.Sprintf("User registered successfully: %s", req.Email), true)

	return user, nil
}

func (s *AuthService) Login(req *models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Log failed login attempt
		s.logActivity("", "", models.ActivityLogin, ipAddress, userAgent,
			fmt.Sprintf("Login failed: invalid 2email %s", req.Email), false)
		return nil, errors.New("invalid credentials")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		// Log failed login attempt
		s.logActivity(user.ID, "", models.ActivityLogin, ipAddress, userAgent,
			fmt.Sprintf("Login failed: invalid password for %s", req.Email), false)
		return nil, errors.New("invalid credentials")
	}

	// Generate JWT token
	expiresAt := time.Now().Add(time.Hour * 24)
	token, err := s.generateJWT(user.ID)
	if err != nil {
		return nil, err
	}

	// Create session
	session := &models.UserSession{
		UserID:     user.ID,
		Token:      token,
		DeviceInfo: s.extractDeviceInfo(userAgent),
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		IsActive:   true,
		ExpiresAt:  expiresAt,
	}

	err = s.sessionRepo.CreateSession(session)
	if err != nil {
		// Log session creation failure but don't fail login
		s.logActivity(user.ID, "", models.ActivityLogin, ipAddress, userAgent,
			fmt.Sprintf("Login successful but session creation failed for %s", req.Email), true)
	} else {
		// Log successful login
		s.logActivity(user.ID, session.ID, models.ActivityLogin, ipAddress, userAgent,
			fmt.Sprintf("Login successful for %s", req.Email), true)
	}

	// Update last login time
	s.userRepo.UpdateLastLogin(user.ID)

	return &models.LoginResponse{
		Token:     token,
		User:      *user,
		SessionID: session.ID,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *AuthService) ValidateToken(tokenString string, ipAddress, userAgent string) (*models.User, error) {
	// First check if session exists and is valid
	session, err := s.sessionRepo.GetSessionByToken(tokenString)
	if err != nil {
		// Log failed token validation
		s.logActivity("", "", models.ActivityTokenValidate, ipAddress, userAgent,
			"Token validation failed: session not found", false)
		return nil, errors.New("invalid token")
	}

	// Update session last used time
	s.sessionRepo.UpdateSessionLastUsed(session.ID)

	// Parse JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})

	if err != nil || !token.Valid {
		// Log failed token validation
		s.logActivity(session.UserID, session.ID, models.ActivityTokenValidate, ipAddress, userAgent,
			"Token validation failed: invalid JWT", false)
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid user ID in token")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		// Log failed token validation
		s.logActivity(userID, session.ID, models.ActivityTokenValidate, ipAddress, userAgent,
			"Token validation failed: user not found", false)
		return nil, errors.New("user not found")
	}

	// Log successful token validation
	s.logActivity(user.ID, session.ID, models.ActivityTokenValidate, ipAddress, userAgent,
		"Token validated successfully", true)

	return user, nil
}

// Session Management Methods
func (s *AuthService) GetUserSessions(userID string) (*models.SessionListResponse, error) {
	sessions, err := s.sessionRepo.GetUserSessions(userID)
	if err != nil {
		return nil, err
	}

	return &models.SessionListResponse{
		Sessions: sessions,
		Total:    len(sessions),
	}, nil
}

func (s *AuthService) RevokeSession(userID, sessionID string, ipAddress, userAgent string) error {
	err := s.sessionRepo.RevokeSession(sessionID)
	if err != nil {
		// Log failed session revocation
		s.logActivity(userID, sessionID, models.ActivitySessionRevoke, ipAddress, userAgent,
			fmt.Sprintf("Session revocation failed: %s", sessionID), false)
		return err
	}

	return nil
}

func (s *AuthService) RevokeAllSessions(userID string, ipAddress, userAgent string) error {
	err := s.sessionRepo.RevokeAllUserSessions(userID)
	if err != nil {
		// Log failed session revocation
		s.logActivity(userID, "", models.ActivitySessionRevoke, ipAddress, userAgent,
			"All sessions revocation failed", false)
		return err
	}

	return nil
}

func (s *AuthService) GetUserActivities(userID string, limit, offset int) (*models.ActivityListResponse, error) {
	activities, err := s.sessionRepo.GetUserActivities(userID, limit, offset)
	if err != nil {
		return nil, err
	}

	total, err := s.sessionRepo.GetUserActivitiesCount(userID)
	if err != nil {
		return nil, err
	}

	return &models.ActivityListResponse{
		Activities: activities,
		Total:      total,
	}, nil
}

// Password Reset Methods
func (s *AuthService) ForgotPassword(req *models.ForgotPasswordRequest, ipAddress, userAgent string) (*models.ForgotPasswordResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Log failed forgot password attempt but don't reveal if email exists
		s.logActivity("", "", models.ActivityForgotPassword, ipAddress, userAgent,
			fmt.Sprintf("Forgot password failed: email %s not found", req.Email), false)

		// Return success message to prevent email enumeration
		return &models.ForgotPasswordResponse{
			Message: "If the email exists, a password reset link has been sent",
			Success: true,
		}, nil
	}

	// Generate secure reset token
	token, err := s.generateSecureToken()
	if err != nil {
		s.logActivity(user.ID, "", models.ActivityForgotPassword, ipAddress, userAgent,
			"Forgot password failed: token generation error", false)
		return nil, errors.New("failed to generate reset token")
	}

	// Create password reset token (expires in 1 hour)
	resetToken := &models.PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour),
		Used:      false,
	}

	err = s.userRepo.CreatePasswordResetToken(resetToken)
	if err != nil {
		s.logActivity(user.ID, "", models.ActivityForgotPassword, ipAddress, userAgent,
			"Forgot password failed: database error", false)
		return nil, errors.New("failed to create reset token")
	}

	// Log successful forgot password request
	s.logActivity(user.ID, "", models.ActivityForgotPassword, ipAddress, userAgent,
		fmt.Sprintf("Password reset token generated for %s", req.Email), true)

	return &models.ForgotPasswordResponse{
		Message: "If the email exists, a password reset link has been sent",
		Success: true,
	}, nil
}

func (s *AuthService) ResetPassword(req *models.ResetPasswordRequest, ipAddress, userAgent string) (*models.ResetPasswordResponse, error) {
	// Get and validate reset token
	resetToken, err := s.userRepo.GetPasswordResetToken(req.Token)
	if err != nil {
		s.logActivity("", "", models.ActivityPasswordReset, ipAddress, userAgent,
			"Password reset failed: invalid or expired token", false)
		return nil, errors.New("invalid or expired reset token")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logActivity(resetToken.UserID, "", models.ActivityPasswordReset, ipAddress, userAgent,
			"Password reset failed: password hashing error", false)
		return nil, errors.New("failed to process new password")
	}

	// Update user password
	err = s.userRepo.UpdatePassword(resetToken.UserID, string(hashedPassword))
	if err != nil {
		s.logActivity(resetToken.UserID, "", models.ActivityPasswordReset, ipAddress, userAgent,
			"Password reset failed: database error", false)
		return nil, errors.New("failed to update password")
	}

	// Mark token as used
	s.userRepo.MarkPasswordResetTokenAsUsed(resetToken.ID)

	// Invalidate all user sessions for security
	s.sessionRepo.RevokeAllUserSessions(resetToken.UserID)

	// Log successful password reset
	s.logActivity(resetToken.UserID, "", models.ActivityPasswordReset, ipAddress, userAgent,
		"Password reset successful", true)

	return &models.ResetPasswordResponse{
		Message: "Password has been reset successfully",
		Success: true,
	}, nil
}

func (s *AuthService) ChangePassword(userID string, req *models.ChangePasswordRequest, ipAddress, userAgent string) (*models.ChangePasswordResponse, error) {
	// Get user to verify current password
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		s.logActivity(userID, "", models.ActivityPasswordChange, ipAddress, userAgent,
			"Password change failed: user not found", false)
		return nil, errors.New("user not found")
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword))
	if err != nil {
		s.logActivity(userID, "", models.ActivityPasswordChange, ipAddress, userAgent,
			"Password change failed: invalid current password", false)
		return nil, errors.New("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logActivity(userID, "", models.ActivityPasswordChange, ipAddress, userAgent,
			"Password change failed: password hashing error", false)
		return nil, errors.New("failed to process new password")
	}

	// Update password
	err = s.userRepo.UpdatePassword(userID, string(hashedPassword))
	if err != nil {
		s.logActivity(userID, "", models.ActivityPasswordChange, ipAddress, userAgent,
			"Password change failed: database error", false)
		return nil, errors.New("failed to update password")
	}

	// Invalidate all other user sessions for security (keep current session)
	s.userRepo.InvalidateUserPasswordResetTokens(userID)

	// Log successful password change
	s.logActivity(userID, "", models.ActivityPasswordChange, ipAddress, userAgent,
		"Password changed successfully", true)

	return &models.ChangePasswordResponse{
		Message: "Password has been changed successfully",
		Success: true,
	}, nil
}

// Profile Management Methods
func (s *AuthService) GetUserProfile(userID string, ipAddress, userAgent string) (*models.UserProfile, error) {
	profile, err := s.userRepo.GetUserProfile(userID)
	if err != nil {
		s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
			"Profile retrieval failed", false)
		return nil, errors.New("failed to retrieve user profile")
	}

	// Log profile access
	s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
		"Profile retrieved successfully", true)

	return profile, nil
}

func (s *AuthService) UpdateProfile(userID string, req *models.UpdateProfileRequest, ipAddress, userAgent string) (*models.UpdateProfileResponse, error) {
	// Check if email is already taken by another user
	if existingUser, _ := s.userRepo.GetByEmail(req.Email); existingUser != nil && existingUser.ID != userID {
		s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
			fmt.Sprintf("Profile update failed: email %s already exists", req.Email), false)
		return nil, errors.New("email is already taken")
	}

	// Update profile
	err := s.userRepo.UpdateProfile(userID, req)
	if err != nil {
		s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
			"Profile update failed: database error", false)
		return nil, errors.New("failed to update profile")
	}

	// Get updated profile
	profile, err := s.userRepo.GetUserProfile(userID)
	if err != nil {
		s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
			"Profile update successful but retrieval failed", true)
		return &models.UpdateProfileResponse{
			Message: "Profile updated successfully",
			Success: true,
		}, nil
	}

	// Log successful profile update
	s.logActivity(userID, "", models.ActivityProfileUpdate, ipAddress, userAgent,
		"Profile updated successfully", true)

	return &models.UpdateProfileResponse{
		Message: "Profile updated successfully",
		Success: true,
		User:    *profile,
	}, nil
}

// Helper Methods
func (s *AuthService) logActivity(userID, sessionID, action, ipAddress, userAgent, details string, success bool) {
	activity := &models.UserActivity{
		UserID:    userID,
		SessionID: sessionID,
		Action:    action,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   details,
		Success:   success,
	}

	// Log activity asynchronously to avoid blocking main operations
	go func() {
		s.sessionRepo.LogActivity(activity)
	}()
}

func (s *AuthService) extractDeviceInfo(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	userAgent = strings.ToLower(userAgent)

	if strings.Contains(userAgent, "mobile") || strings.Contains(userAgent, "android") || strings.Contains(userAgent, "iphone") {
		if strings.Contains(userAgent, "android") {
			return "Android Mobile"
		} else if strings.Contains(userAgent, "iphone") {
			return "iPhone"
		}
		return "Mobile Device"
	}

	if strings.Contains(userAgent, "tablet") || strings.Contains(userAgent, "ipad") {
		return "Tablet"
	}

	if strings.Contains(userAgent, "chrome") {
		return "Chrome Browser"
	} else if strings.Contains(userAgent, "firefox") {
		return "Firefox Browser"
	} else if strings.Contains(userAgent, "safari") {
		return "Safari Browser"
	} else if strings.Contains(userAgent, "edge") {
		return "Edge Browser"
	}

	return "Desktop Browser"
}

func (s *AuthService) generateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *AuthService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32) // 256
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
