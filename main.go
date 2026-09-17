package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/newsand/base-login/features/auth"
	"github.com/newsand/base-login/features/health"
	"github.com/newsand/base-login/features/password"
	"github.com/newsand/base-login/features/twofa"
	"github.com/newsand/base-login/features/users"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
)

func main() {
	cfg := config.Load()

	logger.Init(cfg.LogLevel)
	logger.Info("Starting LoginBuskar Identity Service")
	logger.Info("Version: %s", cfg.Version)

	if err := db.Init(cfg.DatabaseURL); err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer db.Close()

	gin.ForceConsoleColor()
	if cfg.LogLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	v1 := r.Group("/v1")
	{
		health.RegisterRoutes(v1)
		auth.RegisterRoutes(v1)
		users.RegisterRoutes(v1)
		password.RegisterRoutes(v1)
		twofa.RegisterRoutes(v1)
	}

	health.RegisterRoutes(&r.RouterGroup)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("Server listening on :%s", cfg.Port)
		if err := r.Run(":" + cfg.Port); err != nil {
			logger.Fatal("Failed to start server: %v", err)
		}
	}()

	<-quit
	logger.Info("Shutting down server...")
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		logger.Debug("%s %s %d", c.Request.Method, c.Request.URL.Path, c.Writer.Status())
	}
}
