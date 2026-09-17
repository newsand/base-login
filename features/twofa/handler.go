package twofa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
	"github.com/newsand/base-login/internal/middleware"
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

	ctx := c.Request.Context()
	tokenHash := hashToken(req.ChallengeToken)
	pool := db.Pool()

	var challengeID, userID string
	var expiresAt time.Time
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at FROM two_fa_challenges WHERE token_hash = $1
	`, tokenHash).Scan(&challengeID, &userID, &expiresAt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired challenge"})
		return
	}

	if time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired challenge"})
		return
	}

	var secret string
	err = pool.QueryRow(ctx, `SELECT two_fa_secret FROM users WHERE id = $1 AND two_fa_enabled = true`, userID).Scan(&secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "2FA not enabled"})
		return
	}

	if !totp.Validate(req.Code, secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	_, err = pool.Exec(ctx, `DELETE FROM two_fa_challenges WHERE id = $1`, challengeID)
	if err != nil {
		logger.Error("Failed to delete 2FA challenge: %v", err)
	}

	tokens, err := issueTokens(ctx, userID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func Enable(c *gin.Context) {
	userID, _ := c.Get("user_id")
	ctx := c.Request.Context()
	pool := db.Pool()

	var twoFAEnabled bool
	var existingSecret *string
	err := pool.QueryRow(ctx, `SELECT two_fa_enabled, two_fa_secret FROM users WHERE id = $1`, userID).Scan(&twoFAEnabled, &existingSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if twoFAEnabled {
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

		_, err = pool.Exec(ctx, `UPDATE users SET two_fa_secret = $1, updated_at = NOW() WHERE id = $2`, secret, userID)
		if err != nil {
			logger.Error("Failed to save TOTP secret: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"secret":  secret,
			"message": "scan with authenticator app, then POST code to confirm",
		})
		return
	}

	if existingSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "setup 2FA first by calling without code"})
		return
	}

	if !totp.Validate(req.Code, *existingSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	_, err = pool.Exec(ctx, `UPDATE users SET two_fa_enabled = true, updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		logger.Error("Failed to enable 2FA: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

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

	ctx := c.Request.Context()
	pool := db.Pool()

	var twoFAEnabled bool
	var passwordHash, twoFASecret *string
	err := pool.QueryRow(ctx, `SELECT two_fa_enabled, password_hash, two_fa_secret FROM users WHERE id = $1`, userID).Scan(&twoFAEnabled, &passwordHash, &twoFASecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if !twoFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2FA not enabled"})
		return
	}

	verified := false

	if req.Password != "" && passwordHash != nil {
		if err := bcrypt.CompareHashAndPassword([]byte(*passwordHash), []byte(req.Password)); err == nil {
			verified = true
		}
	}

	if req.Code != "" && twoFASecret != nil {
		if totp.Validate(req.Code, *twoFASecret) {
			verified = true
		}
	}

	if !verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	_, err = pool.Exec(ctx, `UPDATE users SET two_fa_enabled = false, two_fa_secret = NULL, updated_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		logger.Error("Failed to disable 2FA: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

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

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func issueTokens(ctx context.Context, userID string) (gin.H, error) {
	cfg := config.Get()
	pool := db.Pool()

	familyID := uuid.New().String()
	jti := uuid.New().String()
	now := time.Now()

	claims := map[string]interface{}{
		"sub":          userID,
		"iat":          now.Unix(),
		"exp":          now.Add(cfg.AccessTokenTTL).Unix(),
		"jti":          jti,
		"2fa_verified": true,
	}

	token := newJWT(claims, cfg.JWTSecret)

	refreshToken := generateOpaqueToken()
	refreshHash := hashToken(refreshToken)
	expiresAt := now.Add(cfg.RefreshTokenTTL)

	_, err := pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, uuid.New().String(), userID, refreshHash, familyID, expiresAt, now)
	if err != nil {
		return nil, err
	}

	return gin.H{
		"access_token":  token,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
	}, nil
}

func generateOpaqueToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newJWT(claims map[string]interface{}, secret string) string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	
	claimsJSON := `{"sub":"` + claims["sub"].(string) + `",` +
		`"iat":` + formatInt64(claims["iat"].(int64)) + `,` +
		`"exp":` + formatInt64(claims["exp"].(int64)) + `,` +
		`"jti":"` + claims["jti"].(string) + `",` +
		`"2fa_verified":true}`
	payload := base64URLEncode([]byte(claimsJSON))
	
	message := header + "." + payload
	h := hmacSHA256([]byte(message), []byte(secret))
	signature := base64URLEncode(h)
	
	return message + "." + signature
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func hmacSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func formatInt64(n int64) string {
	return fmt.Sprintf("%d", n)
}
