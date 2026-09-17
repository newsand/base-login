package password

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
	"github.com/newsand/base-login/internal/middleware"
	"github.com/newsand/base-login/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func RegisterRoutes(r *gin.RouterGroup) {
	pwd := r.Group("/password")
	pwd.Use(middleware.RateLimit())
	{
		pwd.POST("/forgot", Forgot)
		pwd.POST("/reset", Reset)
	}
}

type ForgotRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func Forgot(c *gin.Context) {
	var req ForgotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	cfg := config.Get()

	var user models.User
	if err := db.DB().Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	if user.DisabledAt != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	db.DB().Model(&models.RecoverToken{}).
		Where("user_id = ? AND used_at IS NULL", user.ID).
		Update("used_at", time.Now())

	opaqueToken := models.GenerateOpaqueToken()
	recoverToken := models.RecoverToken{
		UserID:    user.ID,
		TokenHash: models.HashToken(opaqueToken),
		ExpiresAt: time.Now().Add(cfg.RecoverTTL),
	}

	if err := db.DB().Create(&recoverToken).Error; err != nil {
		logger.Error("Failed to create recovery token: %v", err)
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	if cfg.MailerStub {
		logger.Info("[MAILER STUB] Recovery token for %s: %s", req.Email, opaqueToken)
	}

	c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
}

func Reset(c *gin.Context) {
	var req ResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	tokenHash := models.HashToken(req.Token)

	var recoverToken models.RecoverToken
	if err := db.DB().Where("token_hash = ?", tokenHash).First(&recoverToken).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if recoverToken.UsedAt != nil || time.Now().After(recoverToken.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	passwordHash := string(hash)
	db.DB().Model(&models.User{}).Where("id = ?", recoverToken.UserID).Update("password_hash", passwordHash)

	db.DB().Model(&recoverToken).Update("used_at", time.Now())

	db.DB().Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", recoverToken.UserID).
		Update("revoked_at", time.Now())

	logger.Info("Password reset completed for user: %s", recoverToken.UserID)
	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}
