package auth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
	"github.com/newsand/base-login/internal/middleware"
	"github.com/newsand/base-login/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func RegisterRoutes(r *gin.RouterGroup) {
	auth := r.Group("/auth")
	auth.Use(middleware.RateLimit())
	{
		auth.POST("/login", Login)
		auth.POST("/refresh", Refresh)
		auth.POST("/logout", middleware.JWTAuth(), Logout)
		auth.POST("/magic-link", RequestMagicLink)
		auth.POST("/magic-link/consume", ConsumeMagicLink)
	}

	me := r.Group("/me")
	me.Use(middleware.JWTAuth())
	{
		me.GET("", GetMe)
	}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type MagicLinkRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type MagicLinkConsumeRequest struct {
	Token string `json:"token" binding:"required"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	lockoutKey := "login:" + req.Email
	if middleware.CheckLockout(c.Request.Context(), lockoutKey) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked"})
		return
	}

	var user models.User
	if err := db.DB().Where("email = ?", req.Email).First(&user).Error; err != nil {
		middleware.RecordFailedAttempt(lockoutKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if user.DisabledAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account disabled"})
		return
	}

	if user.PasswordHash == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		middleware.RecordFailedAttempt(lockoutKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	middleware.ClearLockout(lockoutKey)

	if user.TwoFAEnabled && user.TwoFASecret != nil {
		challengeToken, err := createTwoFAChallenge(user.ID)
		if err != nil {
			logger.Error("Failed to create 2FA challenge: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa":    true,
			"challenge_token": challengeToken,
		})
		return
	}

	tokens, err := issueTokens(user.ID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenHash := models.HashToken(req.RefreshToken)

	var refresh models.RefreshToken
	if err := db.DB().Where("token_hash = ?", tokenHash).First(&refresh).Error; err != nil {
		logger.Debug("Refresh token not found: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if refresh.RevokedAt != nil {
		logger.Warn("Reuse detection: revoking family %s", refresh.FamilyID)
		db.DB().Model(&models.RefreshToken{}).
			Where("family_id = ? AND revoked_at IS NULL", refresh.FamilyID).
			Update("revoked_at", time.Now())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if time.Now().After(refresh.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	var user models.User
	if err := db.DB().First(&user, "id = ?", refresh.UserID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}
	if user.DisabledAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account disabled"})
		return
	}

	result := db.DB().Model(&models.RefreshToken{}).
		Where("id = ? AND revoked_at IS NULL", refresh.ID).
		Update("revoked_at", time.Now())
	if result.RowsAffected == 0 {
		logger.Warn("Reuse detection (TOCTOU): revoking family %s", refresh.FamilyID)
		db.DB().Model(&models.RefreshToken{}).
			Where("family_id = ? AND revoked_at IS NULL", refresh.FamilyID).
			Update("revoked_at", time.Now())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	tokens, err := issueTokensWithFamily(refresh.UserID, refresh.FamilyID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func Logout(c *gin.Context) {
	userID, _ := c.Get("user_id")

	db.DB().Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now())

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func GetMe(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var user models.User
	if err := db.DB().First(&user, "id = ?", userID).Error; err != nil {
		logger.Error("Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"email":       user.Email,
		"nome":        user.Nome,
		"2fa_enabled": user.TwoFAEnabled,
	})
}

func RequestMagicLink(c *gin.Context) {
	var req MagicLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	var user models.User
	if err := db.DB().Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	if user.DisabledAt != nil || user.PasswordHash == nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	token, err := createMagicToken(user.ID)
	if err != nil {
		logger.Error("Failed to create magic token: %v", err)
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	cfg := config.Get()
	if cfg.MailerStub {
		logger.Info("[MAILER STUB] Magic link for %s: %s", user.Email, token)
	}

	c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
}

func ConsumeMagicLink(c *gin.Context) {
	var req MagicLinkConsumeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenHash := models.HashToken(req.Token)

	var magic models.MagicToken
	if err := db.DB().Where("token_hash = ?", tokenHash).First(&magic).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if magic.UsedAt != nil || time.Now().After(magic.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	now := time.Now()
	db.DB().Model(&magic).Update("used_at", now)

	var user models.User
	if err := db.DB().First(&user, "id = ?", magic.UserID).Error; err != nil || user.DisabledAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if user.TwoFAEnabled && user.TwoFASecret != nil {
		challengeToken, err := createTwoFAChallenge(user.ID)
		if err != nil {
			logger.Error("Failed to create 2FA challenge: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa":    true,
			"challenge_token": challengeToken,
		})
		return
	}

	tokens, err := issueTokens(user.ID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func issueTokens(userID string) (gin.H, error) {
	familyID := uuid.New().String()
	return issueTokensWithFamily(userID, familyID)
}

func issueTokensWithFamily(userID, familyID string) (gin.H, error) {
	cfg := config.Get()

	jti := uuid.New().String()
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":          userID,
		"iat":          now.Unix(),
		"exp":          now.Add(cfg.AccessTokenTTL).Unix(),
		"jti":          jti,
		"2fa_verified": true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return nil, err
	}

	opaqueToken := models.GenerateOpaqueToken()
	refreshToken := models.RefreshToken{
		UserID:    userID,
		TokenHash: models.HashToken(opaqueToken),
		FamilyID:  familyID,
		ExpiresAt: now.Add(cfg.RefreshTokenTTL),
	}

	if err := db.DB().Create(&refreshToken).Error; err != nil {
		return nil, err
	}

	return gin.H{
		"access_token":  accessToken,
		"refresh_token": opaqueToken,
		"token_type":    "Bearer",
		"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
	}, nil
}

func createMagicToken(userID string) (string, error) {
	cfg := config.Get()

	db.DB().Model(&models.MagicToken{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Update("used_at", time.Now())

	opaqueToken := models.GenerateOpaqueToken()
	magic := models.MagicToken{
		UserID:    userID,
		TokenHash: models.HashToken(opaqueToken),
		ExpiresAt: time.Now().Add(cfg.MagicLinkTTL),
	}

	if err := db.DB().Create(&magic).Error; err != nil {
		return "", err
	}

	return opaqueToken, nil
}

func createTwoFAChallenge(userID string) (string, error) {
	db.DB().Where("user_id = ?", userID).Delete(&models.TwoFAChallenge{})

	opaqueToken := models.GenerateOpaqueToken()
	challenge := models.TwoFAChallenge{
		UserID:    userID,
		TokenHash: models.HashToken(opaqueToken),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := db.DB().Create(&challenge).Error; err != nil {
		return "", err
	}

	return opaqueToken, nil
}
