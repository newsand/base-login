package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID           string     `gorm:"type:uuid;primaryKey" json:"id"`
	Email        string     `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash *string    `gorm:"column:password_hash" json:"-"`
	Nome         string     `gorm:"not null" json:"nome"`
	Telefone     *string    `json:"telefone,omitempty"`
	CPF          *string    `json:"cpf,omitempty"`
	TwoFAEnabled bool       `gorm:"column:two_fa_enabled;default:false" json:"2fa_enabled"`
	TwoFASecret  *string    `gorm:"column:two_fa_secret" json:"-"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	DisabledAt   *time.Time `json:"disabled_at,omitempty"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

type RefreshToken struct {
	ID        string     `gorm:"type:uuid;primaryKey"`
	UserID    string     `gorm:"type:uuid;index;not null"`
	TokenHash string     `gorm:"uniqueIndex;not null"`
	FamilyID  string     `gorm:"type:uuid;index;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	RevokedAt *time.Time `gorm:"index"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if rt.ID == "" {
		rt.ID = uuid.New().String()
	}
	return nil
}

type Invite struct {
	ID        string     `gorm:"type:uuid;primaryKey"`
	Email     string     `gorm:"index;not null"`
	TokenHash string     `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	UsedAt    *time.Time
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (i *Invite) BeforeCreate(tx *gorm.DB) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	return nil
}

type MagicToken struct {
	ID        string     `gorm:"type:uuid;primaryKey"`
	UserID    string     `gorm:"type:uuid;index;not null"`
	TokenHash string     `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	UsedAt    *time.Time
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (mt *MagicToken) BeforeCreate(tx *gorm.DB) error {
	if mt.ID == "" {
		mt.ID = uuid.New().String()
	}
	return nil
}

type RecoverToken struct {
	ID        string     `gorm:"type:uuid;primaryKey"`
	UserID    string     `gorm:"type:uuid;index;not null"`
	TokenHash string     `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time  `gorm:"not null"`
	UsedAt    *time.Time
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (rt *RecoverToken) BeforeCreate(tx *gorm.DB) error {
	if rt.ID == "" {
		rt.ID = uuid.New().String()
	}
	return nil
}

type TwoFAChallenge struct {
	ID        string    `gorm:"type:uuid;primaryKey"`
	UserID    string    `gorm:"type:uuid;index;not null"`
	TokenHash string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

func (c *TwoFAChallenge) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}

func GenerateOpaqueToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
