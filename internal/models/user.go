package models

import (
	"time"
)

type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Password  string    `json:"-" db:"password"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Name     string `json:"name" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token     string      `json:"token"`
	User      User        `json:"user"`
	SessionID string      `json:"session_id"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// Session Management Models
type UserSession struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	Token       string    `json:"token" db:"token"`
	DeviceInfo  string    `json:"device_info" db:"device_info"`
	IPAddress   string    `json:"ip_address" db:"ip_address"`
	UserAgent   string    `json:"user_agent" db:"user_agent"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	LastUsedAt  time.Time `json:"last_used_at" db:"last_used_at"`
}

type UserActivity struct {
	ID          string    `json:"id" db:"id"`
	UserID      string    `json:"user_id" db:"user_id"`
	SessionID   string    `json:"session_id" db:"session_id"`
	Action      string    `json:"action" db:"action"`
	IPAddress   string    `json:"ip_address" db:"ip_address"`
	UserAgent   string    `json:"user_agent" db:"user_agent"`
	Details     string    `json:"details" db:"details"`
	Success     bool      `json:"success" db:"success"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// Session Management Requests/Responses
type SessionListResponse struct {
	Sessions []UserSession `json:"sessions"`
	Total    int           `json:"total"`
}

type ActivityListResponse struct {
	Activities []UserActivity `json:"activities"`
	Total      int            `json:"total"`
}

type RevokeSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// Password Reset Models
type PasswordResetToken struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Used      bool      `json:"used" db:"used"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=6"`
}

// Profile Management Models
type UpdateProfileRequest struct {
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

type UserProfile struct {
	ID                string    `json:"id"`
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	ActiveSessionsCount int      `json:"active_sessions_count"`
	TotalActivities   int       `json:"total_activities"`
}

// Response Models
type ForgotPasswordResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

type ChangePasswordResponse struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

type UpdateProfileResponse struct {
	Message string      `json:"message"`
	Success bool        `json:"success"`
	User    UserProfile `json:"user"`
}

// Activity Types
const (
	ActivityLogin          = "login"
	ActivityLogout         = "logout"
	ActivityRegister       = "register"
	ActivityTokenValidate  = "token_validate"
	ActivitySessionRevoke  = "session_revoke"
	ActivityPasswordChange = "password_change"
	ActivityProfileUpdate  = "profile_update"
	ActivityPasswordReset  = "password_reset"
	ActivityForgotPassword = "forgot_password"
)
