package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/logger"
	"github.com/newsand/base-login/internal/middleware"
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

	ctx := c.Request.Context()
	lockoutKey := "login:" + req.Email

	if middleware.CheckLockout(ctx, lockoutKey) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked"})
		return
	}

	user, err := getUserByEmail(ctx, req.Email)
	if err != nil {
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
		challengeToken, err := createTwoFAChallenge(ctx, user.ID)
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

	tokens, err := issueTokens(ctx, user.ID)
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

	ctx := c.Request.Context()
	tokenHash := hashToken(req.RefreshToken)

	refresh, err := getRefreshToken(ctx, tokenHash)
	if err != nil {
		logger.Debug("Refresh token not found: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if refresh.RevokedAt != nil {
		logger.Warn("Reuse detection: revoking family %s", refresh.FamilyID)
		if err := revokeFamily(ctx, refresh.FamilyID); err != nil {
			logger.Error("Failed to revoke family: %v", err)
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if time.Now().After(refresh.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	if err := revokeRefreshToken(ctx, refresh.ID); err != nil {
		logger.Error("Failed to revoke old refresh token: %v", err)
	}

	tokens, err := issueTokensWithFamily(ctx, refresh.UserID, refresh.FamilyID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func Logout(c *gin.Context) {
	userID, _ := c.Get("user_id")

	ctx := c.Request.Context()
	if err := revokeAllUserRefreshTokens(ctx, userID.(string)); err != nil {
		logger.Error("Failed to revoke refresh tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func GetMe(c *gin.Context) {
	userID, _ := c.Get("user_id")

	ctx := c.Request.Context()
	user, err := getUserByID(ctx, userID.(string))
	if err != nil {
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

	ctx := c.Request.Context()
	user, err := getUserByEmail(ctx, req.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	if user.DisabledAt != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	if user.PasswordHash == nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a magic link will be sent"})
		return
	}

	token, err := createMagicToken(ctx, user.ID)
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

	ctx := c.Request.Context()
	tokenHash := hashToken(req.Token)

	magic, err := getMagicToken(ctx, tokenHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if magic.UsedAt != nil || time.Now().After(magic.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if err := markMagicTokenUsed(ctx, magic.ID); err != nil {
		logger.Error("Failed to mark magic token used: %v", err)
	}

	user, err := getUserByID(ctx, magic.UserID)
	if err != nil || user.DisabledAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	if user.TwoFAEnabled && user.TwoFASecret != nil {
		challengeToken, err := createTwoFAChallenge(ctx, user.ID)
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

	tokens, err := issueTokens(ctx, user.ID)
	if err != nil {
		logger.Error("Failed to issue tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

type User struct {
	ID           string
	Email        string
	PasswordHash *string
	Nome         string
	Telefone     *string
	CPF          *string
	TwoFAEnabled bool
	TwoFASecret  *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DisabledAt   *time.Time
}

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

type MagicToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

func getUserByEmail(ctx context.Context, email string) (*User, error) {
	pool := db.Pool()
	var u User
	err := pool.QueryRow(ctx, `
		SELECT id, email, password_hash, nome, telefone, cpf, two_fa_enabled, two_fa_secret, created_at, updated_at, disabled_at
		FROM users WHERE email = $1
	`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Nome, &u.Telefone, &u.CPF, &u.TwoFAEnabled, &u.TwoFASecret, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func getUserByID(ctx context.Context, id string) (*User, error) {
	pool := db.Pool()
	var u User
	err := pool.QueryRow(ctx, `
		SELECT id, email, password_hash, nome, telefone, cpf, two_fa_enabled, two_fa_secret, created_at, updated_at, disabled_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Nome, &u.Telefone, &u.CPF, &u.TwoFAEnabled, &u.TwoFASecret, &u.CreatedAt, &u.UpdatedAt, &u.DisabledAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func issueTokens(ctx context.Context, userID string) (gin.H, error) {
	familyID := uuid.New().String()
	return issueTokensWithFamily(ctx, userID, familyID)
}

func issueTokensWithFamily(ctx context.Context, userID, familyID string) (gin.H, error) {
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

	refreshToken := generateOpaqueToken()
	refreshHash := hashToken(refreshToken)
	expiresAt := now.Add(cfg.RefreshTokenTTL)

	pool := db.Pool()
	_, err = pool.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, uuid.New().String(), userID, refreshHash, familyID, expiresAt, now)
	if err != nil {
		return nil, err
	}

	return gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(cfg.AccessTokenTTL.Seconds()),
	}, nil
}

func getRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	pool := db.Pool()
	var rt RefreshToken
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, family_id, expires_at, revoked_at, created_at
		FROM refresh_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.FamilyID, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func revokeRefreshToken(ctx context.Context, id string) error {
	pool := db.Pool()
	_, err := pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1`, id)
	return err
}

func revokeFamily(ctx context.Context, familyID string) error {
	pool := db.Pool()
	_, err := pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
	return err
}

func revokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	pool := db.Pool()
	_, err := pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func createMagicToken(ctx context.Context, userID string) (string, error) {
	cfg := config.Get()
	pool := db.Pool()

	_, err := pool.Exec(ctx, `UPDATE magic_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return "", err
	}

	token := generateOpaqueToken()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(cfg.MagicLinkTTL)

	_, err = pool.Exec(ctx, `
		INSERT INTO magic_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, uuid.New().String(), userID, tokenHash, expiresAt)
	if err != nil {
		return "", err
	}

	return token, nil
}

func getMagicToken(ctx context.Context, tokenHash string) (*MagicToken, error) {
	pool := db.Pool()
	var mt MagicToken
	err := pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM magic_tokens WHERE token_hash = $1
	`, tokenHash).Scan(&mt.ID, &mt.UserID, &mt.TokenHash, &mt.ExpiresAt, &mt.UsedAt, &mt.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &mt, nil
}

func markMagicTokenUsed(ctx context.Context, id string) error {
	pool := db.Pool()
	_, err := pool.Exec(ctx, `UPDATE magic_tokens SET used_at = NOW() WHERE id = $1`, id)
	return err
}

func createTwoFAChallenge(ctx context.Context, userID string) (string, error) {
	pool := db.Pool()

	_, err := pool.Exec(ctx, `DELETE FROM two_fa_challenges WHERE user_id = $1`, userID)
	if err != nil {
		return "", err
	}

	token := generateOpaqueToken()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(5 * time.Minute)

	_, err = pool.Exec(ctx, `
		INSERT INTO two_fa_challenges (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, uuid.New().String(), userID, tokenHash, expiresAt)
	if err != nil {
		return "", err
	}

	return token, nil
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
