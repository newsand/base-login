package users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/newsand/base-login/features/auth"
	"github.com/newsand/base-login/internal/config"
	"github.com/newsand/base-login/internal/db"
	"github.com/newsand/base-login/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	err = testDB.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.Invite{},
		&models.MagicToken{},
		&models.TwoFAChallenge{},
	)
	if err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}

	db.SetTestDB(testDB)
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/v1")
	RegisterRoutes(v1)
	return r
}

func setupTestRouterWithAuth() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/v1")
	RegisterRoutes(v1)
	auth.RegisterRoutes(v1)
	return r
}

func TestAcceptInviteRejectsExistingAccountWithPassword(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	hash, _ := bcrypt.GenerateFromPassword([]byte("existing123"), bcrypt.MinCost)
	passwordHash := string(hash)
	existingUser := &models.User{
		Email:        "existing@example.com",
		PasswordHash: &passwordHash,
		Nome:         "Existing User",
	}
	db.DB().Create(existingUser)

	invite := &models.Invite{
		Email:     "existing@example.com",
		TokenHash: models.HashToken("invite-token-123"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(invite)

	acceptBody, _ := json.Marshal(map[string]string{
		"token":    "invite-token-123",
		"password": "newpassword123",
		"nome":     "Attacker",
	})
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewBuffer(acceptBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for existing account with password, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.DB().Where("email = ?", "existing@example.com").First(&user)
	
	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte("existing123")); err != nil {
		t.Error("password should NOT have been changed")
	}
	if user.Nome != "Existing User" {
		t.Error("nome should NOT have been changed")
	}
}

func TestAcceptInviteAllowsPendingUserWithoutPassword(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	pendingUser := &models.User{
		Email:        "pending@example.com",
		PasswordHash: nil,
		Nome:         "Pending User",
	}
	db.DB().Create(pendingUser)

	invite := &models.Invite{
		Email:     "pending@example.com",
		TokenHash: models.HashToken("pending-invite-token"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(invite)

	acceptBody, _ := json.Marshal(map[string]string{
		"token":    "pending-invite-token",
		"password": "newpassword123",
		"nome":     "Activated User",
	})
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewBuffer(acceptBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK for pending user, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.DB().Where("email = ?", "pending@example.com").First(&user)
	
	if user.PasswordHash == nil {
		t.Error("password should have been set")
	}
	if user.Nome != "Activated User" {
		t.Errorf("nome should have been updated, got %s", user.Nome)
	}
}

func TestAcceptInviteCreatesNewUser(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	invite := &models.Invite{
		Email:     "newuser@example.com",
		TokenHash: models.HashToken("new-user-token"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(invite)

	acceptBody, _ := json.Marshal(map[string]string{
		"token":    "new-user-token",
		"password": "newpassword123",
		"nome":     "New User",
	})
	req := httptest.NewRequest("POST", "/v1/invites/accept", bytes.NewBuffer(acceptBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 OK for new user, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	if err := db.DB().Where("email = ?", "newuser@example.com").First(&user).Error; err != nil {
		t.Error("user should have been created")
	}
	if user.PasswordHash == nil {
		t.Error("password should have been set")
	}
	if user.Nome != "New User" {
		t.Errorf("nome should be 'New User', got %s", user.Nome)
	}
}

func TestDisableUserRevokesRefreshTokens(t *testing.T) {
	setupTestDB(t)
	cfg := config.Load()
	cfg.ServiceKeys = []string{"test-service-key"}

	router := setupTestRouter()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	passwordHash := string(hash)
	user := &models.User{
		Email:        "disable-test@example.com",
		PasswordHash: &passwordHash,
		Nome:         "Disable Test",
	}
	db.DB().Create(user)

	opaqueToken := "test-refresh-token-abc123"
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: models.HashToken(opaqueToken),
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(refreshToken)

	var activeBefore int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&activeBefore)
	if activeBefore != 1 {
		t.Fatalf("expected 1 active token before disable, got %d", activeBefore)
	}

	patchBody, _ := json.Marshal(map[string]string{
		"disabled_at": "now",
	})
	req := httptest.NewRequest("PATCH", "/v1/users/"+user.ID, bytes.NewBuffer(patchBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-service-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PATCH disable failed: %d %s", w.Code, w.Body.String())
	}

	var activeAfter int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&activeAfter)
	if activeAfter != 0 {
		t.Errorf("expected 0 active tokens after disable via PATCH, got %d", activeAfter)
	}

	var revokedToken models.RefreshToken
	db.DB().Where("token_hash = ?", models.HashToken(opaqueToken)).First(&revokedToken)
	if revokedToken.RevokedAt == nil {
		t.Error("refresh token should be revoked after PATCH disable")
	}
}

func TestDisableUserRefreshRejected(t *testing.T) {
	setupTestDB(t)
	cfg := config.Load()
	cfg.ServiceKeys = []string{"test-service-key"}

	router := setupTestRouterWithAuth()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	passwordHash := string(hash)
	user := &models.User{
		Email:        "disable-refresh@example.com",
		PasswordHash: &passwordHash,
		Nome:         "Disable Refresh Test",
	}
	db.DB().Create(user)

	opaqueToken := "refresh-to-be-rejected"
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: models.HashToken(opaqueToken),
		FamilyID:  "family-reject",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(refreshToken)

	patchBody, _ := json.Marshal(map[string]string{
		"disabled_at": "now",
	})
	req := httptest.NewRequest("PATCH", "/v1/users/"+user.ID, bytes.NewBuffer(patchBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-service-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PATCH disable failed: %d %s", w.Code, w.Body.String())
	}

	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": opaqueToken,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("refresh after disable should return 401, got %d: %s", w.Code, w.Body.String())
	}
}
