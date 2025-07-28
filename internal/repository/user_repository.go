package repository

import (
	"auth-service/internal/models"
	"database/sql"

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
