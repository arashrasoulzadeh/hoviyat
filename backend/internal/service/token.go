package service

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token")

// Claims carries the subject plus the caller's tenant-scoped roles. A token
// is always minted for exactly one tenant context (empty TenantID/Roles for
// a "not yet in any tenant" pre-tenant-selection token); switching tenants
// (PRD §6 tenant-switcher) means issuing a fresh token via
// AuthService.SwitchTenant rather than mutating claims in place. ABAC
// attributes arrive with the ACL/ABAC build stage.
type Claims struct {
	UserID   string   `json:"uid"`
	TenantID string   `json:"tid,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

type TokenService struct {
	secret          []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewTokenService(secret string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{secret: []byte(secret), accessTokenTTL: accessTTL, refreshTokenTTL: refreshTTL}
}

func (s *TokenService) GenerateAccessToken(userID, tenantID string, roles []string) (string, error) {
	return s.generate(userID, tenantID, roles, s.accessTokenTTL)
}

func (s *TokenService) GenerateRefreshToken(userID, tenantID string, roles []string) (string, error) {
	return s.generate(userID, tenantID, roles, s.refreshTokenTTL)
}

func (s *TokenService) generate(userID, tenantID string, roles []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		TenantID: tenantID,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Subject:   userID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *TokenService) Parse(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
