package config

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/lib/pq"
)

type Config struct {
	// Master database configuration
	DBMasterHost     string
	DBMasterPort     string
	DBMasterName     string
	DBMasterUser     string
	DBMasterPassword string

	// Replica database configuration
	DBReplicaHost     string
	DBReplicaPort     string
	DBReplicaName     string
	DBReplicaUser     string
	DBReplicaPassword string

	JWTSecret  string
}

func Load() *Config {
	// Load .env file if it exists
	loadEnvFile()

	return &Config{
		// Master database configuration
		DBMasterHost:     getEnv("DB_MASTER_HOST", getEnv("DB_HOST", "localhost")),
		DBMasterPort:     getEnv("DB_MASTER_PORT", getEnv("DB_PORT", "5432")),
		DBMasterName:     getEnv("DB_MASTER_NAME", getEnv("DB_NAME", "ticketing_db")),
		DBMasterUser:     getEnv("DB_MASTER_USER", getEnv("DB_USER", "postgres")),
		DBMasterPassword: getEnv("DB_MASTER_PASSWORD", getEnv("DB_PASSWORD", "password")),

		// Replica database configuration (fallback to master if not specified)
		DBReplicaHost:     getEnv("DB_REPLICA_HOST", getEnv("DB_MASTER_HOST", getEnv("DB_HOST", "localhost"))),
		DBReplicaPort:     getEnv("DB_REPLICA_PORT", getEnv("DB_MASTER_PORT", getEnv("DB_PORT", "5432"))),
		DBReplicaName:     getEnv("DB_REPLICA_NAME", getEnv("DB_MASTER_NAME", getEnv("DB_NAME", "ticketing_db"))),
		DBReplicaUser:     getEnv("DB_REPLICA_USER", getEnv("DB_MASTER_USER", getEnv("DB_USER", "postgres"))),
		DBReplicaPassword: getEnv("DB_REPLICA_PASSWORD", getEnv("DB_MASTER_PASSWORD", getEnv("DB_PASSWORD", "password"))),

		JWTSecret:  getEnv("JWT_SECRET", "your-jwt-secret-key"),
	}
}

// loadEnvFile loads environment variables from .env file
func loadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		log.Println("No .env file found, using system environment variables")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			os.Setenv(key, value)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading .env file: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// DBConnections holds both master and replica database connections
type DBConnections struct {
	Master  *sql.DB
	Replica *sql.DB
}

func ConnectMasterDB(cfg *Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable search_path=public",
		cfg.DBMasterHost, cfg.DBMasterPort, cfg.DBMasterUser, cfg.DBMasterPassword, cfg.DBMasterName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Connecting to Master PostgreSQL: %s:%s/%s\n", cfg.DBMasterHost, cfg.DBMasterPort, cfg.DBMasterName)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func ConnectReplicaDB(cfg *Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable search_path=public",
		cfg.DBReplicaHost, cfg.DBReplicaPort, cfg.DBReplicaUser, cfg.DBReplicaPassword, cfg.DBReplicaName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Connecting to Replica PostgreSQL: %s:%s/%s\n", cfg.DBReplicaHost, cfg.DBReplicaPort, cfg.DBReplicaName)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func ConnectDatabases(cfg *Config) (*DBConnections, error) {
	masterDB, err := ConnectMasterDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to master database: %v", err)
	}

	replicaDB, err := ConnectReplicaDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to replica database: %v", err)
	}

	return &DBConnections{
		Master:  masterDB,
		Replica: replicaDB,
	}, nil
}

// ConnectDB maintains backward compatibility - connects to master database
func ConnectDB(cfg *Config) (*sql.DB, error) {
	return ConnectMasterDB(cfg)
}

// AutoMigrate creates the necessary database tables if they don't exist
func AutoMigrate(db *sql.DB) error {
	// Create users table
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		name VARCHAR(255) NOT NULL,
		last_login_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Add last_login_at column if it doesn't exist (for existing installations)
	DO $$ 
	BEGIN 
		IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='last_login_at') THEN
			ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP;
		END IF;
	END $$;

	-- Create trigger to update updated_at column
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $$
	BEGIN
		NEW.updated_at = CURRENT_TIMESTAMP;
		RETURN NEW;
	END;
	$$ language 'plpgsql';

	DROP TRIGGER IF EXISTS update_users_updated_at ON users;
	CREATE TRIGGER update_users_updated_at
		BEFORE UPDATE ON users
		FOR EACH ROW
		EXECUTE FUNCTION update_updated_at_column();
	`

	_, err := db.Exec(createUsersTable)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create user sessions table
	createSessionsTable := `
	CREATE TABLE IF NOT EXISTS user_sessions (
		id VARCHAR(36) PRIMARY KEY,
		user_id VARCHAR(36) NOT NULL,
		token TEXT NOT NULL,
		device_info VARCHAR(500),
		ip_address VARCHAR(45),
		user_agent TEXT,
		is_active BOOLEAN DEFAULT true,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);
	CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active, expires_at);

	-- Create trigger for user_sessions updated_at
	DROP TRIGGER IF EXISTS update_user_sessions_updated_at ON user_sessions;
	CREATE TRIGGER update_user_sessions_updated_at
		BEFORE UPDATE ON user_sessions
		FOR EACH ROW
		EXECUTE FUNCTION update_updated_at_column();
	`

	_, err = db.Exec(createSessionsTable)
	if err != nil {
		return fmt.Errorf("failed to create user_sessions table: %v", err)
	}

	// Create user activities table
	createActivitiesTable := `
	CREATE TABLE IF NOT EXISTS user_activities (
		id VARCHAR(36) PRIMARY KEY,
		user_id VARCHAR(36) NOT NULL,
		session_id VARCHAR(36),
		action VARCHAR(100) NOT NULL,
		ip_address VARCHAR(45),
		user_agent TEXT,
		details TEXT,
		success BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (session_id) REFERENCES user_sessions(id) ON DELETE SET NULL
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_user_activities_user_id ON user_activities(user_id);
	CREATE INDEX IF NOT EXISTS idx_user_activities_session_id ON user_activities(session_id);
	CREATE INDEX IF NOT EXISTS idx_user_activities_action ON user_activities(action);
	CREATE INDEX IF NOT EXISTS idx_user_activities_created_at ON user_activities(created_at);
	`

	_, err = db.Exec(createActivitiesTable)
	if err != nil {
		return fmt.Errorf("failed to create user_activities table: %v", err)
	}

	// Create password reset tokens table
	createPasswordResetTable := `
	CREATE TABLE IF NOT EXISTS password_reset_tokens (
		id VARCHAR(36) PRIMARY KEY,
		user_id VARCHAR(36) NOT NULL,
		token VARCHAR(255) UNIQUE NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used BOOLEAN DEFAULT false,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
	CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
	CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_used ON password_reset_tokens(used);
	`

	_, err = db.Exec(createPasswordResetTable)
	if err != nil {
		return fmt.Errorf("failed to create password_reset_tokens table: %v", err)
	}

	log.Println("Database migration completed successfully")
	return nil
}
