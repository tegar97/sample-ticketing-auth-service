package main

import (
	"log"
	"net/http"
	"os"

	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/repository"
	"auth-service/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	dbConnections, err := config.ConnectDatabases(cfg)
	if err != nil {
		log.Fatal("Failed to connect to databases:", err)
	}

	// Run auto migration on master database
	if err := config.AutoMigrate(dbConnections.Master); err != nil {
		log.Fatal("Failed to run database migration:", err)
	}

	userRepo := repository.NewUserRepository(dbConnections.Master, dbConnections.Replica)
	authService := service.NewAuthService(userRepo, cfg.JWTSecret)
	authHandler := handler.NewAuthHandler(authService)

	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	})

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "auth-service update",
			"status":  "running",
			"version": "1.0.0",
		})
	})

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "auth-service",
		})
	})

	r.GET("/forgot-password", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"feat":   "forgot-password ",
		})
	})

	api := r.Group("/api/v1")
	{
		api.POST("/register", authHandler.Register)
		api.POST("/login", authHandler.Login)
		api.GET("/profile", authHandler.GetProfile)
		api.GET("/validate", authHandler.ValidateToken)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	log.Printf("Auth service starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
