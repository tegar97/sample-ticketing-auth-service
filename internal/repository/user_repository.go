package repository

import (
	"auth-service/internal/models"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type UserRepository struct {
	masterDB  *sql.DB
	replicaDB *sql.DB
}

func NewUserRepository(masterDB, replicaDB *sql.DB) *UserRepository {
	return &UserRepository{
		masterDB:  masterDB,
		replicaDB: replicaDB,
	}
}

func (r *UserRepository) Create(user *models.User) error {
	user.ID = uuid.New().String()

	query := `
        INSERT INTO users (id, email, password, name)
        VALUES ($1, $2, $3, $4)
        RETURNING created_at, updated_at
    `

	err := r.masterDB.QueryRow(query, user.ID, user.Email, user.Password, user.Name).
		Scan(&user.CreatedAt, &user.UpdatedAt)

	return err
}

func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	user := &models.User{}

	query := `
        SELECT id, email, password, name, created_at, updated_at
        FROM users
        WHERE email = $1
    `

	err := r.replicaDB.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *UserRepository) GetByID(id string) (*models.User, error) {
	user := &models.User{}

	query := `
        SELECT id, email, password, name, created_at, updated_at
        FROM users
        WHERE id = $1
    `

	err := r.replicaDB.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

// Password Reset Methods
func (r *UserRepository) CreatePasswordResetToken(token *models.PasswordResetToken) error {
	token.ID = uuid.New().String()
	token.CreatedAt = time.Now()

	query := `
        INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `

	_, err := r.masterDB.Exec(query,
		token.ID, token.UserID, token.Token, token.ExpiresAt, token.Used, token.CreatedAt,
	)

	return err
}

func (r *UserRepository) GetPasswordResetToken(token string) (*models.PasswordResetToken, error) {
	resetToken := &models.PasswordResetToken{}

	query := `
        SELECT id, user_id, token, expires_at, used, created_at
        FROM password_reset_tokens
        WHERE token = $1 AND used = false AND expires_at > NOW()
    `

	err := r.replicaDB.QueryRow(query, token).Scan(
		&resetToken.ID, &resetToken.UserID, &resetToken.Token,
		&resetToken.ExpiresAt, &resetToken.Used, &resetToken.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return resetToken, nil
}

func (r *UserRepository) MarkPasswordResetTokenAsUsed(tokenID string) error {
	query := `
        UPDATE password_reset_tokens 
        SET used = true 
        WHERE id = $1
    `

	_, err := r.masterDB.Exec(query, tokenID)
	return err
}

func (r *UserRepository) InvalidateUserPasswordResetTokens(userID string) error {
	query := `
        UPDATE password_reset_tokens 
        SET used = true 
        WHERE user_id = $1 AND used = false
    `

	_, err := r.masterDB.Exec(query, userID)
	return err
}

// Profile Management Methods
func (r *UserRepository) UpdatePassword(userID, newPassword string) error {
	query := `
        UPDATE users 
        SET password = $1, updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
    `

	_, err := r.masterDB.Exec(query, newPassword, userID)
	return err
}

func (r *UserRepository) UpdateProfile(userID string, req *models.UpdateProfileRequest) error {
	query := `
        UPDATE users 
        SET name = $1, email = $2, updated_at = CURRENT_TIMESTAMP
        WHERE id = $3
    `

	_, err := r.masterDB.Exec(query, req.Name, req.Email, userID)
	return err
}

func (r *UserRepository) UpdateLastLogin(userID string) error {
	query := `
        UPDATE users 
        SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
    `

	_, err := r.masterDB.Exec(query, userID)
	return err
}

func (r *UserRepository) GetUserProfile(userID string) (*models.UserProfile, error) {
	profile := &models.UserProfile{}

	query := `
        SELECT u.id, u.email, u.name, u.created_at, u.updated_at, u.last_login_at,
               COALESCE(s.active_sessions, 0) as active_sessions_count,
               COALESCE(a.total_activities, 0) as total_activities
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*) as active_sessions
            FROM user_sessions 
            WHERE is_active = true AND expires_at > NOW()
            GROUP BY user_id
        ) s ON u.id = s.user_id
        LEFT JOIN (
            SELECT user_id, COUNT(*) as total_activities
            FROM user_activities
            GROUP BY user_id
        ) a ON u.id = a.user_id
        WHERE u.id = $1
    `

	var lastLoginAt sql.NullTime
	err := r.replicaDB.QueryRow(query, userID).Scan(
		&profile.ID, &profile.Email, &profile.Name,
		&profile.CreatedAt, &profile.UpdatedAt, &lastLoginAt,
		&profile.ActiveSessionsCount, &profile.TotalActivities,
	)

	if err != nil {
		return nil, err
	}

	if lastLoginAt.Valid {
		profile.LastLoginAt = &lastLoginAt.Time
	}

	return profile, nil
}

// Cleanup expired password reset tokens
func (r *UserRepository) CleanupExpiredPasswordResetTokens() error {
	query := `
        DELETE FROM password_reset_tokens 
        WHERE expires_at <= NOW() OR used = true
    `

	_, err := r.masterDB.Exec(query)
	return err
}
