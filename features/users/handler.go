package users

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

const BcryptCost = 12

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

	var existing models.User
	if err := db.DB().Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
		return
	}

	user := models.User{
		Email:    req.Email,
		Nome:     req.Nome,
		Telefone: req.Telefone,
		CPF:      req.CPF,
	}

	if req.Password != nil && *req.Password != "" {
		if len(*req.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), BcryptCost)
		if err != nil {
			logger.Error("Failed to hash password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		h := string(hash)
		user.PasswordHash = &h
	}

	if err := db.DB().Create(&user).Error; err != nil {
		logger.Error("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	logger.Info("User created: %s (%s)", user.ID, req.Email)
	c.JSON(http.StatusCreated, gin.H{
		"id":         user.ID,
		"email":      user.Email,
		"nome":       user.Nome,
		"created_at": user.CreatedAt,
	})
}

func ListUsers(c *gin.Context) {
	var users []models.User
	if err := db.DB().Order("created_at DESC").Limit(100).Find(&users).Error; err != nil {
		logger.Error("Failed to list users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	result := make([]gin.H, len(users))
	for i, u := range users {
		result[i] = gin.H{
			"id":          u.ID,
			"email":       u.Email,
			"nome":        u.Nome,
			"telefone":    u.Telefone,
			"cpf":         u.CPF,
			"2fa_enabled": u.TwoFAEnabled,
			"created_at":  u.CreatedAt,
			"updated_at":  u.UpdatedAt,
			"disabled_at": u.DisabledAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{"users": result})
}

func GetUser(c *gin.Context) {
	id := c.Param("id")

	var user models.User
	if err := db.DB().First(&user, "id = ?", id).Error; err != nil {
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

	var user models.User
	if err := db.DB().First(&user, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	updates := make(map[string]interface{})

	if req.Email != nil && *req.Email != user.Email {
		var existing models.User
		if err := db.DB().Where("email = ?", *req.Email).First(&existing).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
			return
		}
		updates["email"] = *req.Email
	}

	if req.Nome != nil {
		updates["nome"] = *req.Nome
	}
	if req.Telefone != nil {
		updates["telefone"] = *req.Telefone
	}
	if req.CPF != nil {
		updates["cpf"] = *req.CPF
	}
	disabling := false
	if req.DisabledAt != nil {
		if *req.DisabledAt == "" {
			updates["disabled_at"] = nil
		} else {
			updates["disabled_at"] = time.Now()
			disabling = true
		}
	}

	if len(updates) > 0 {
		if err := db.DB().Model(&user).Updates(updates).Error; err != nil {
			logger.Error("Failed to update user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	if disabling {
		db.DB().Model(&models.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL", id).
			Update("revoked_at", time.Now())
		logger.Info("Revoked all refresh tokens for disabled user: %s", id)
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

	cfg := config.Get()

	db.DB().Model(&models.Invite{}).
		Where("email = ? AND used_at IS NULL", req.Email).
		Update("used_at", time.Now())

	opaqueToken := models.GenerateOpaqueToken()
	invite := models.Invite{
		Email:     req.Email,
		TokenHash: models.HashToken(opaqueToken),
		ExpiresAt: time.Now().Add(cfg.InviteTTL),
	}

	if err := db.DB().Create(&invite).Error; err != nil {
		logger.Error("Failed to create invite: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	response := gin.H{
		"message": "invite sent",
		"email":   req.Email,
	}

	if cfg.MailerStub {
		logger.Info("[MAILER STUB] Invite for %s: %s", req.Email, opaqueToken)
		// Mailer is stubbed (no real OOB delivery), so the caller needs the
		// token back to be able to hand it to the invitee itself. Never
		// returned when a real mailer is configured — token stays OOB then.
		response["token"] = opaqueToken
		response["expires_at"] = invite.ExpiresAt
	}

	logger.Info("Invite created for: %s", req.Email)
	c.JSON(http.StatusCreated, response)
}

func AcceptInvite(c *gin.Context) {
	var req AcceptInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	tokenHash := models.HashToken(req.Token)

	var invite models.Invite
	if err := db.DB().Where("token_hash = ?", tokenHash).First(&invite).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired invite"})
		return
	}

	if invite.UsedAt != nil || time.Now().After(invite.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired invite"})
		return
	}

	var existingUser models.User
	userExists := db.DB().Where("email = ?", invite.Email).First(&existingUser).Error == nil

	if userExists && existingUser.PasswordHash != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "account already exists"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), BcryptCost)
	if err != nil {
		logger.Error("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	nome := req.Nome
	if nome == "" {
		nome = invite.Email
	}

	var userID string
	passwordHash := string(hash)

	if userExists {
		userID = existingUser.ID
		db.DB().Model(&existingUser).Updates(map[string]interface{}{
			"password_hash": passwordHash,
			"nome":          nome,
		})
	} else {
		newUser := models.User{
			Email:        invite.Email,
			PasswordHash: &passwordHash,
			Nome:         nome,
		}
		if err := db.DB().Create(&newUser).Error; err != nil {
			logger.Error("Failed to create user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		userID = newUser.ID
	}

	db.DB().Model(&invite).Update("used_at", time.Now())

	logger.Info("Invite accepted: %s (%s)", userID, invite.Email)
	c.JSON(http.StatusOK, gin.H{
		"message": "account activated",
		"user_id": userID,
	})
}
