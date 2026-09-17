package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/newsand/base-login/internal/config"
)

type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

type lockoutEntry struct {
	failCount  int
	lockedUntil time.Time
}

var (
	rateLimits = make(map[string]*rateLimitEntry)
	lockouts   = make(map[string]*lockoutEntry)
	mu         sync.RWMutex
)

func RateLimit() gin.HandlerFunc {
	cfg := config.Get()
	return func(c *gin.Context) {
		key := c.ClientIP() + ":" + c.Request.URL.Path
		
		mu.Lock()
		entry, exists := rateLimits[key]
		now := time.Now()
		
		if !exists || now.After(entry.windowEnd) {
			rateLimits[key] = &rateLimitEntry{
				count:     1,
				windowEnd: now.Add(cfg.RateLimitWindow),
			}
			mu.Unlock()
			c.Next()
			return
		}
		
		entry.count++
		if entry.count > cfg.RateLimitRequests {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}
		mu.Unlock()
		c.Next()
	}
}

func CheckLockout(ctx context.Context, identifier string) bool {
	cfg := config.Get()
	mu.RLock()
	entry, exists := lockouts[identifier]
	mu.RUnlock()
	
	if !exists {
		return false
	}
	
	now := time.Now()
	if now.Before(entry.lockedUntil) {
		return true
	}
	
	if entry.failCount >= cfg.LockoutThreshold && now.After(entry.lockedUntil) {
		mu.Lock()
		delete(lockouts, identifier)
		mu.Unlock()
	}
	
	return false
}

func RecordFailedAttempt(identifier string) bool {
	cfg := config.Get()
	mu.Lock()
	defer mu.Unlock()
	
	entry, exists := lockouts[identifier]
	now := time.Now()
	
	if !exists {
		lockouts[identifier] = &lockoutEntry{
			failCount:  1,
			lockedUntil: time.Time{},
		}
		return false
	}
	
	if now.After(entry.lockedUntil) && entry.failCount >= cfg.LockoutThreshold {
		entry.failCount = 1
		entry.lockedUntil = time.Time{}
		return false
	}
	
	entry.failCount++
	if entry.failCount >= cfg.LockoutThreshold {
		entry.lockedUntil = now.Add(cfg.LockoutDuration)
		return true
	}
	
	return false
}

func ClearLockout(identifier string) {
	mu.Lock()
	delete(lockouts, identifier)
	mu.Unlock()
}
