package main

import (
	"fmt"
	"log"

	"auth-service/internal/config"
)

func main() {
	fmt.Println("Testing .env loading and auto migration...")

	// Test config loading
	cfg := config.Load()

	fmt.Printf("Loaded configuration:\n")
	fmt.Printf("DB_HOST: %s\n", cfg.DBHost)
	fmt.Printf("DB_PORT: %s\n", cfg.DBPort)
	fmt.Printf("DB_NAME: %s\n", cfg.DBName)
	fmt.Printf("DB_USER: %s\n", cfg.DBUser)
	fmt.Printf("JWT_SECRET: %s\n", cfg.JWTSecret)

	// Test database connection and migration
	fmt.Println("\nTesting database connection and migration...")
	db, err := config.ConnectDB(cfg)
	if err != nil {
		log.Printf("Failed to connect to database: %v", err)
		fmt.Println("Note: This is expected if database is not accessible")
		return
	}
	defer db.Close()

	// Test migration
	if err := config.AutoMigrate(db); err != nil {
		log.Printf("Failed to run migration: %v", err)
		return
	}

	fmt.Println("✓ Database connection and migration successful!")
}
