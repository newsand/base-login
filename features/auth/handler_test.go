package auth

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

func createTestUser(t *testing.T, email, password string) *models.User {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	passwordHash := string(hash)
	user := &models.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Nome:         "Test User",
	}
	if err := db.DB().Create(user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

func TestRefreshTokenRotation(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	user := createTestUser(t, "test@example.com", "password123")

	loginBody, _ := json.Marshal(map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}

	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	refreshToken1 := loginResp["refresh_token"].(string)

	var countBefore int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&countBefore)
	if countBefore != 1 {
		t.Fatalf("expected 1 active refresh token before rotation, got %d", countBefore)
	}

	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken1,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", w.Code, w.Body.String())
	}

	var refreshResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &refreshResp)
	refreshToken2 := refreshResp["refresh_token"].(string)

	if refreshToken1 == refreshToken2 {
		t.Error("refresh token should have rotated to a new value")
	}

	var countAfter int64
	db.DB().Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Count(&countAfter)
	if countAfter != 1 {
		t.Errorf("expected 1 active refresh token after rotation, got %d", countAfter)
	}

	var oldToken models.RefreshToken
	oldTokenHash := models.HashToken(refreshToken1)
	db.DB().Where("token_hash = ?", oldTokenHash).First(&oldToken)
	if oldToken.RevokedAt == nil {
		t.Error("old refresh token should be revoked after rotation")
	}
}

func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	createTestUser(t, "reuse@example.com", "password123")

	loginBody, _ := json.Marshal(map[string]string{
		"email":    "reuse@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	refreshToken1 := loginResp["refresh_token"].(string)

	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken1,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d", w.Code)
	}

	var refreshResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &refreshResp)
	refreshToken2 := refreshResp["refresh_token"].(string)

	reuseBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken1,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(reuseBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("reuse of old token should return 401, got %d", w.Code)
	}

	validBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken2,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(validBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("token from same family should be revoked after reuse detection, got %d", w.Code)
	}

	var oldToken models.RefreshToken
	db.DB().Where("token_hash = ?", models.HashToken(refreshToken1)).First(&oldToken)

	var activeCount int64
	db.DB().Model(&models.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", oldToken.FamilyID).
		Count(&activeCount)
	if activeCount != 0 {
		t.Errorf("all tokens in family should be revoked, got %d active", activeCount)
	}
}

func TestRefreshDisabledUserRejected(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	user := createTestUser(t, "disabled@example.com", "password123")

	loginBody, _ := json.Marshal(map[string]string{
		"email":    "disabled@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	refreshToken := loginResp["refresh_token"].(string)

	now := time.Now()
	db.DB().Model(user).Update("disabled_at", now)

	refreshBody, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(refreshBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("refresh for disabled user should return 401, got %d", w.Code)
	}
}

func TestLoginDisabledUserRejected(t *testing.T) {
	setupTestDB(t)
	config.Load()
	router := setupTestRouter()

	user := createTestUser(t, "login-disabled@example.com", "password123")

	now := time.Now()
	db.DB().Model(user).Update("disabled_at", now)

	loginBody, _ := json.Marshal(map[string]string{
		"email":    "login-disabled@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("login for disabled user should return 401, got %d", w.Code)
	}
}
