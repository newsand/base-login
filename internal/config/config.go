package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port              string
	DatabaseURL       string
	LogLevel          string
	JWTSecret         string
	ServiceKeys       []string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	MagicLinkTTL      time.Duration
	InviteTTL         time.Duration
	RecoverTTL        time.Duration
	RateLimitRequests int
	RateLimitWindow   time.Duration
	LockoutThreshold  int
	LockoutDuration   time.Duration
	MailerStub        bool
	Version           string
}

var cfg *Config

func Load() *Config {
	if cfg != nil {
		return cfg
	}

	cfg = &Config{
		Port:              getEnv("PORT", "8080"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/loginbuskar?sslmode=disable"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		JWTSecret:         getEnv("JWT_SECRET", "change-me-in-production"),
		ServiceKeys:       parseServiceKeys(getEnv("SERVICE_KEYS", "")),
		AccessTokenTTL:    getDurationEnv("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:   getDurationEnv("REFRESH_TOKEN_TTL", 14*24*time.Hour),
		MagicLinkTTL:      getDurationEnv("MAGIC_LINK_TTL", 15*time.Minute),
		InviteTTL:         getDurationEnv("INVITE_TTL", 7*24*time.Hour),
		RecoverTTL:        getDurationEnv("RECOVER_TTL", 1*time.Hour),
		RateLimitRequests: getIntEnv("RATE_LIMIT_REQUESTS", 5),
		RateLimitWindow:   getDurationEnv("RATE_LIMIT_WINDOW", 1*time.Minute),
		LockoutThreshold:  getIntEnv("LOCKOUT_THRESHOLD", 5),
		LockoutDuration:   getDurationEnv("LOCKOUT_DURATION", 15*time.Minute),
		MailerStub:        getBoolEnv("MAILER_STUB", true),
		Version:           "alfa",
	}

	return cfg
}

func Get() *Config {
	if cfg == nil {
		return Load()
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getBoolEnv(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func parseServiceKeys(s string) []string {
	if s == "" {
		return nil
	}
	keys := strings.Split(s, ",")
	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if trimmed := strings.TrimSpace(k); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
