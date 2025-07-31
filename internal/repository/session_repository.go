package repository

import (
	"auth-service/internal/models"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type SessionRepository struct {
	masterDB  *sql.DB
	replicaDB *sql.DB
}

func NewSessionRepository(masterDB, replicaDB *sql.DB) *SessionRepository {
	return &SessionRepository{
		masterDB:  masterDB,
		replicaDB: replicaDB,
	}
}

// Session Management
func (r *SessionRepository) CreateSession(session *models.UserSession) error {
	session.ID = uuid.New().String()
	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()
	session.LastUsedAt = time.Now()

	query := `
        INSERT INTO user_sessions (id, user_id, token, device_info, ip_address, user_agent, is_active, expires_at, created_at, updated_at, last_used_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `

	_, err := r.masterDB.Exec(query,
		session.ID, session.UserID, session.Token, session.DeviceInfo,
		session.IPAddress, session.UserAgent, session.IsActive, session.ExpiresAt,
		session.CreatedAt, session.UpdatedAt, session.LastUsedAt,
	)

	return err
}

func (r *SessionRepository) GetSessionByToken(token string) (*models.UserSession, error) {
	session := &models.UserSession{}

	query := `
        SELECT id, user_id, token, device_info, ip_address, user_agent, is_active, expires_at, created_at, updated_at, last_used_at
        FROM user_sessions
        WHERE token = $1 AND is_active = true AND expires_at > NOW()
    `

	err := r.replicaDB.QueryRow(query, token).Scan(
		&session.ID, &session.UserID, &session.Token, &session.DeviceInfo,
		&session.IPAddress, &session.UserAgent, &session.IsActive, &session.ExpiresAt,
		&session.CreatedAt, &session.UpdatedAt, &session.LastUsedAt,
	)

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (r *SessionRepository) GetUserSessions(userID string) ([]models.UserSession, error) {
	query := `
        SELECT id, user_id, token, device_info, ip_address, user_agent, is_active, expires_at, created_at, updated_at, last_used_at
        FROM user_sessions
        WHERE user_id = $1 AND is_active = true AND expires_at > NOW()
        ORDER BY last_used_at DESC
    `

	rows, err := r.replicaDB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.UserSession
	for rows.Next() {
		var session models.UserSession
		err := rows.Scan(
			&session.ID, &session.UserID, &session.Token, &session.DeviceInfo,
			&session.IPAddress, &session.UserAgent, &session.IsActive, &session.ExpiresAt,
			&session.CreatedAt, &session.UpdatedAt, &session.LastUsedAt,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *SessionRepository) UpdateSessionLastUsed(sessionID string) error {
	query := `
        UPDATE user_sessions 
        SET last_used_at = NOW(), updated_at = NOW()
        WHERE id = $1
    `

	_, err := r.masterDB.Exec(query, sessionID)
	return err
}

func (r *SessionRepository) RevokeSession(sessionID string) error {
	query := `
        UPDATE user_sessions 
        SET is_active = false, updated_at = NOW()
        WHERE id = $1
    `

	_, err := r.masterDB.Exec(query, sessionID)
	return err
}

func (r *SessionRepository) RevokeAllUserSessions(userID string) error {
	query := `
        UPDATE user_sessions 
        SET is_active = false, updated_at = NOW()
        WHERE user_id = $1 AND is_active = true
    `

	_, err := r.masterDB.Exec(query, userID)
	return err
}

func (r *SessionRepository) CleanupExpiredSessions() error {
	query := `
        UPDATE user_sessions 
        SET is_active = false, updated_at = NOW()
        WHERE expires_at <= NOW() AND is_active = true
    `

	_, err := r.masterDB.Exec(query)
	return err
}

// Activity Logging
func (r *SessionRepository) LogActivity(activity *models.UserActivity) error {
	activity.ID = uuid.New().String()
	activity.CreatedAt = time.Now()

	query := `
        INSERT INTO user_activities (id, user_id, session_id, action, ip_address, user_agent, details, success, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `

	_, err := r.masterDB.Exec(query,
		activity.ID, activity.UserID, activity.SessionID, activity.Action,
		activity.IPAddress, activity.UserAgent, activity.Details, activity.Success,
		activity.CreatedAt,
	)

	return err
}

func (r *SessionRepository) GetUserActivities(userID string, limit int, offset int) ([]models.UserActivity, error) {
	query := `
        SELECT id, user_id, session_id, action, ip_address, user_agent, details, success, created_at
        FROM user_activities
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `

	rows, err := r.replicaDB.Query(query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activities []models.UserActivity
	for rows.Next() {
		var activity models.UserActivity
		err := rows.Scan(
			&activity.ID, &activity.UserID, &activity.SessionID, &activity.Action,
			&activity.IPAddress, &activity.UserAgent, &activity.Details, &activity.Success,
			&activity.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		activities = append(activities, activity)
	}

	return activities, nil
}

func (r *SessionRepository) GetUserActivitiesCount(userID string) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM user_activities WHERE user_id = $1`
	err := r.replicaDB.QueryRow(query, userID).Scan(&count)
	return count, err
}
