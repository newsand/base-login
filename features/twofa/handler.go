package twofa

import (
	"crypto/rand"
	"encoding/base32"
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
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func RegisterRoutes(r *gin.RouterGroup) {
	tfa := r.Group("/auth/2fa")
	tfa.Use(middleware.RateLimit())
	{
		tfa.POST("/verify", Verify)
	}

	me := r.Group("/me/2fa")
	me.Use(middleware.JWTAuth())
	{
		me.POST("/enable", Enable)
		me.POST("/disable", Disable)
	}
}

type VerifyRequest struct {
	ChallengeToken string `json:"challenge_token" binding:"required"`
	Code           string `json:"code" binding:"required"`
}

type EnableRequest struct {
	Code string `json:"code" binding:"required"`
}

type DisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func Verify(c *gin.Context) {
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenHash := models.HashToken(req.ChallengeToken)

	var challenge models.TwoFAChallenge
	if err := db.DB().Where("token_hash = ?", tokenHash).First(&challenge).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired challenge"})
		return
	}

	if time.Now().After(challenge.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired challenge"})
		return
	}

	var user models.User
	if err := db.DB().Where("id = ? AND two_fa_enabled = ?", challenge.UserID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "2FA not enabled"})
		return
	}

	if user.TwoFASecret == nil || !totp.Validate(req.Code, *user.TwoFASecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	db.DB().Delete(&challenge)

	tokens, err := issueTokens(user.ID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func Enable(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var user models.User
	if err := db.DB().First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if user.TwoFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2FA already enabled"})
		return
	}

	var req EnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		secret, err := generateTOTPSecret()
		if err != nil {
			logger.Error("Failed to generate TOTP secret: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		db.DB().Model(&user).Update("two_fa_secret", secret)

		c.JSON(http.StatusOK, gin.H{
			"secret":  secret,
			"message": "scan with authenticator app, then POST code to confirm",
		})
		return
	}

	if user.TwoFASecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "setup 2FA first by calling without code"})
		return
	}

	if !totp.Validate(req.Code, *user.TwoFASecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	db.DB().Model(&user).Update("two_fa_enabled", true)

	logger.Info("2FA enabled for user: %s", userID)
	c.JSON(http.StatusOK, gin.H{"message": "2FA enabled"})
}

func Disable(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var req DisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password or code required"})
		return
	}

	if req.Password == "" && req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password or code required"})
		return
	}

	var user models.User
	if err := db.DB().First(&user, "id = ?", userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if !user.TwoFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2FA not enabled"})
		return
	}

	verified := false

	if req.Password != "" && user.PasswordHash != nil {
		if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err == nil {
			verified = true
		}
	}

	if req.Code != "" && user.TwoFASecret != nil {
		if totp.Validate(req.Code, *user.TwoFASecret) {
			verified = true
		}
	}

	if !verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	db.DB().Model(&user).Updates(map[string]interface{}{
		"two_fa_enabled": false,
		"two_fa_secret":  nil,
	})

	logger.Info("2FA disabled for user: %s", userID)
	c.JSON(http.StatusOK, gin.H{"message": "2FA disabled"})
}

func generateTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func issueTokens(userID string) (gin.H, error) {
	cfg := config.Get()

	familyID := uuid.New().String()
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
