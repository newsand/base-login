package users

import (
	"context"
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
	users := r.Group("/users")
	users.Use(middleware.ServiceKeyAuth())
	{
		users.POST("", CreateUser)
		users.GET("", ListUsers)
		users.GET("/:id", GetUser)
		users.PATCH("/:id", UpdateUser)
	}

	invites := r.Group("/invites")
	{
		invites.POST("", middleware.ServiceKeyAuth(), CreateInvite)
		invites.POST("/accept", middleware.RateLimit(), AcceptInvite)
	}
}

type CreateUserRequest struct {
	Email    string  `json:"email" binding:"required,email"`
	Nome     string  `json:"nome" binding:"required"`
	Password *string `json:"password"`
	Telefone *string `json:"telefone"`
	CPF      *string `json:"cpf"`
}

type UpdateUserRequest struct {
	Email      *string `json:"email"`
	Nome       *string `json:"nome"`
	Telefone   *string `json:"telefone"`
	CPF        *string `json:"cpf"`
	DisabledAt *string `json:"disabled_at"`
}

type CreateInviteRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type AcceptInviteRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
	Nome     string `json:"nome"`
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	ctx := c.Request.Context()

	existing, _ := getUserByEmail(ctx, req.Email)
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}

	userID := uuid.New().String()
	now := time.Now()

	var passwordHash *string
	if req.Password != nil && *req.Password != "" {
		if len(*req.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Failed to hash password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		h := string(hash)
		passwordHash = &h
	}

	pool := db.Pool()
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, nome, telefone, cpf, two_fa_enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, false, $7, $7)
	`, userID, req.Email, passwordHash, req.Nome, req.Telefone, req.CPF, now)
	if err != nil {
		logger.Error("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	logger.Info("User created: %s (%s)", userID, req.Email)
	c.JSON(http.StatusCreated, gin.H{
		"id":         userID,
		"email":      req.Email,
		"nome":       req.Nome,
		"created_at": now,
	})
}

func ListUsers(c *gin.Context) {
	ctx := c.Request.Context()
	pool := db.Pool()

	rows, err := pool.Query(ctx, `
		SELECT id, email, nome, telefone, cpf, two_fa_enabled, created_at, updated_at, disabled_at
		FROM users ORDER BY created_at DESC LIMIT 100
	`)
	if err != nil {
		logger.Error("Failed to list users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	defer rows.Close()

	users := make([]gin.H, 0)
	for rows.Next() {
		var id, email, nome string
		var telefone, cpf *string
		var twoFAEnabled bool
		var createdAt, updatedAt time.Time
		var disabledAt *time.Time

		if err := rows.Scan(&id, &email, &nome, &telefone, &cpf, &twoFAEnabled, &createdAt, &updatedAt, &disabledAt); err != nil {
			continue
		}

		users = append(users, gin.H{
			"id":          id,
			"email":       email,
			"nome":        nome,
			"telefone":    telefone,
			"cpf":         cpf,
			"2fa_enabled": twoFAEnabled,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
			"disabled_at": disabledAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func GetUser(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	user, err := getUserByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          user.ID,
		"email":       user.Email,
		"nome":        user.Nome,
		"telefone":    user.Telefone,
		"cpf":         user.CPF,
		"2fa_enabled": user.TwoFAEnabled,
		"created_at":  user.CreatedAt,
		"updated_at":  user.UpdatedAt,
		"disabled_at": user.DisabledAt,
	})
}

func UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()

	user, err := getUserByID(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	pool := db.Pool()

	if req.Email != nil && *req.Email != user.Email {
		existing, _ := getUserByEmail(ctx, *req.Email)
		if existing != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
			return
		}
		_, err = pool.Exec(ctx, `UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2`, *req.Email, id)
		if err != nil {
			logger.Error("Failed to update email: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	if req.Nome != nil {
		_, err = pool.Exec(ctx, `UPDATE users SET nome = $1, updated_at = NOW() WHERE id = $2`, *req.Nome, id)
		if err != nil {
			logger.Error("Failed to update nome: %v", err)
		}
	}

	if req.Telefone != nil {
		_, err = pool.Exec(ctx, `UPDATE users SET telefone = $1, updated_at = NOW() WHERE id = $2`, *req.Telefone, id)
		if err != nil {
			logger.Error("Failed to update telefone: %v", err)
		}
	}

	if req.CPF != nil {
		_, err = pool.Exec(ctx, `UPDATE users SET cpf = $1, updated_at = NOW() WHERE id = $2`, *req.CPF, id)
		if err != nil {
			logger.Error("Failed to update cpf: %v", err)
		}
	}

	if req.DisabledAt != nil {
		if *req.DisabledAt == "" {
			_, err = pool.Exec(ctx, `UPDATE users SET disabled_at = NULL, updated_at = NOW() WHERE id = $1`, id)
		} else {
			_, err = pool.Exec(ctx, `UPDATE users SET disabled_at = NOW(), updated_at = NOW() WHERE id = $1`, id)
		}
		if err != nil {
			logger.Error("Failed to update disabled_at: %v", err)
		}
	}

	logger.Info("User updated: %s", id)
	c.JSON(http.StatusOK, gin.H{"message": "user updated"})
}

func CreateInvite(c *gin.Context) {
	var req CreateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx := c.Request.Context()
	cfg := config.Get()
	pool := db.Pool()

	_, err := pool.Exec(ctx, `UPDATE invites SET used_at = NOW() WHERE email = $1 AND used_at IS NULL`, req.Email)
	if err != nil {
		logger.Error("Failed to invalidate old invites: %v", err)
	}

	token := generateOpaqueToken()
	tokenHash := hashToken(token)
	expiresAt := time.Now().Add(cfg.InviteTTL)

	_, err = pool.Exec(ctx, `
		INSERT INTO invites (id, email, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, uuid.New().String(), req.Email, tokenHash, expiresAt)
	if err != nil {
		logger.Error("Failed to create invite: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if cfg.MailerStub {
		logger.Info("[MAILER STUB] Invite for %s: %s", req.Email, token)
	}

	logger.Info("Invite created for: %s", req.Email)
	c.JSON(http.StatusCreated, gin.H{
		"message": "invite sent",
		"email":   req.Email,
	})
}

func AcceptInvite(c *gin.Context) {
	var req AcceptInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tokenHash := hashToken(req.Token)
	pool := db.Pool()

	var inviteID, email string
	var expiresAt time.Time
	var usedAt *time.Time
	err := pool.QueryRow(ctx, `
		SELECT id, email, expires_at, used_at FROM invites WHERE token_hash = $1
	`, tokenHash).Scan(&inviteID, &email, &expiresAt, &usedAt)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired invite"})
		return
	}

	if usedAt != nil || time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired invite"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	nome := req.Nome
	if nome == "" {
		nome = email
	}

	existingUser, _ := getUserByEmail(ctx, email)
	var userID string

	if existingUser != nil {
		userID = existingUser.ID
		_, err = pool.Exec(ctx, `
			UPDATE users SET password_hash = $1, nome = COALESCE(NULLIF($2, ''), nome), disabled_at = NULL, updated_at = NOW() WHERE id = $3
		`, string(hash), nome, userID)
		if err != nil {
			logger.Error("Failed to update user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	} else {
		userID = uuid.New().String()
		now := time.Now()
		_, err = pool.Exec(ctx, `
			INSERT INTO users (id, email, password_hash, nome, two_fa_enabled, created_at, updated_at)
			VALUES ($1, $2, $3, $4, false, $5, $5)
		`, userID, email, string(hash), nome, now)
		if err != nil {
			logger.Error("Failed to create user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	_, err = pool.Exec(ctx, `UPDATE invites SET used_at = NOW() WHERE id = $1`, inviteID)
	if err != nil {
		logger.Error("Failed to mark invite used: %v", err)
	}

	logger.Info("Invite accepted: %s (%s)", userID, email)
	c.JSON(http.StatusOK, gin.H{
		"message": "account activated",
		"user_id": userID,
	})
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

func generateOpaqueToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
