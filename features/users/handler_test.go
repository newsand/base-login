package users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
	config.Load()

	hash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	passwordHash := string(hash)
	user := &models.User{
		Email:        "disable-test@example.com",
		PasswordHash: &passwordHash,
		Nome:         "Disable Test",
	}
	db.DB().Create(user)

	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: models.HashToken("refresh-token-1"),
		FamilyID:  "family-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.DB().Create(refreshToken)

	var activeBefore int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&activeBefore)
	if activeBefore != 1 {
		t.Fatalf("expected 1 active token before disable, got %d", activeBefore)
	}

	now := time.Now()
	db.DB().Model(user).Update("disabled_at", now)
	db.DB().Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", user.ID).
		Update("revoked_at", now)

	var activeAfter int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&activeAfter)
	if activeAfter != 0 {
		t.Errorf("expected 0 active tokens after disable, got %d", activeAfter)
	}
}
