package service

import (
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
			fmt.Sprintf("Login failed: invalid email %s", req.Email), false)
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

	// Simple device detection based on user agent
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
