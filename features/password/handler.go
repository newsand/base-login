package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
	"github.com/newsand/base-login/internal/middleware"
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

	ctx := c.Request.Context()
	cfg := config.Get()
	pool := db.Pool()

	var userID string
	var disabledAt *time.Time
	err := pool.QueryRow(ctx, `SELECT id, disabled_at FROM users WHERE email = $1`, req.Email).Scan(&userID, &disabledAt)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	if disabledAt != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	_, err = pool.Exec(ctx, `UPDATE recover_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		logger.Error("Failed to invalidate old recovery tokens: %v", err)
	}

	token := generateOpaqueToken()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(cfg.RecoverTTL)

	_, err = pool.Exec(ctx, `
		INSERT INTO recover_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, uuid.New().String(), userID, tokenHash, expiresAt)
	if err != nil {
		logger.Error("Failed to create recovery token: %v", err)
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
		return
	}

	if cfg.MailerStub {
		logger.Info("[MAILER STUB] Recovery token for %s: %s", req.Email, token)
	}

	c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a recovery link will be sent"})
}

func Reset(c *gin.Context) {
	var req ResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tokenHash := hashToken(req.Token)
	pool := db.Pool()

	var tokenID, userID string
	var expiresAt time.Time
	var usedAt *time.Time
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at, used_at FROM recover_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&tokenID, &userID, &expiresAt, &usedAt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if usedAt != nil || time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	_, err = pool.Exec(ctx, `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`, string(hash), userID)
	if err != nil {
		logger.Error("Failed to update password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	_, err = pool.Exec(ctx, `UPDATE recover_tokens SET used_at = NOW() WHERE id = $1`, tokenID)
	if err != nil {
		logger.Error("Failed to mark recovery token used: %v", err)
	}

	_, err = pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		logger.Error("Failed to revoke refresh tokens: %v", err)
	}

	logger.Info("Password reset completed for user: %s", userID)
	c.JSON(http.StatusOK, gin.H{"message": "password reset successful"})
}

func generateOpaqueToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
