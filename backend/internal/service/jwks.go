package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrNoActiveSigningKey = errors.New("no active signing key")
)

type JWKSService struct {
	keys        domain.SigningKeyRepository
	currentKey  *domain.SigningKey
	keyMutex    chan struct{} // simple mutex
}

func NewJWKSService(keys domain.SigningKeyRepository) *JWKSService {
	s := &JWKSService{
		keys:     keys,
		keyMutex: make(chan struct{}, 1),
	}
	s.keyMutex <- struct{}{} // initialize
	return s
}

func (s *JWKSService) Initialize(ctx context.Context) error {
	// Try to find existing active key
	activeKey, err := s.keys.FindActive(ctx)
	if err != nil {
		return err
	}
	if activeKey != nil {
		s.currentKey = activeKey
		return nil
	}

	// Generate new RSA key pair
	return s.RotateKey(ctx)
}

func (s *JWKSService) RotateKey(ctx context.Context) error {
	<-s.keyMutex
	defer func() { s.keyMutex <- struct{}{} }()

	// Deactivate current key
	if s.currentKey != nil {
		s.currentKey.IsActive = false
		if err := s.keys.Update(ctx, s.currentKey); err != nil {
			return err
		}
	}

	// Generate new RSA key pair (2048 bits)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Encode private key
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Generate key ID
	keyID := generateKeyID()

	// Create signing key record
	expiresAt := time.Now().Add(90 * 24 * time.Hour) // 90 days
	signingKey := &domain.SigningKey{
		KeyID:      keyID,
		Algorithm:  "RS256",
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		IsActive:   true,
		ExpiresAt:  &expiresAt,
	}

	if err := s.keys.Create(ctx, signingKey); err != nil {
		return err
	}

	s.currentKey = signingKey
	return nil
}

func (s *JWKSService) GetActiveKey(ctx context.Context) (*domain.SigningKey, error) {
	<-s.keyMutex
	defer func() { s.keyMutex <- struct{}{} }()

	if s.currentKey != nil && (s.currentKey.ExpiresAt == nil || time.Now().Before(*s.currentKey.ExpiresAt)) {
		return s.currentKey, nil
	}

	// Try to find active key in DB
	activeKey, err := s.keys.FindActive(ctx)
	if err != nil {
		return nil, err
	}
	if activeKey != nil && (activeKey.ExpiresAt == nil || time.Now().Before(*activeKey.ExpiresAt)) {
		s.currentKey = activeKey
		return activeKey, nil
	}

	// Rotate if no valid key
	if err := s.RotateKey(ctx); err != nil {
		return nil, err
	}
	return s.currentKey, nil
}

func (s *JWKSService) GetKeyByID(ctx context.Context, keyID string) (*domain.SigningKey, error) {
	return s.keys.FindByKeyID(ctx, keyID)
}

func (s *JWKSService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	keys, err := s.keys.List(ctx)
	if err != nil {
		return nil, err
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{},
	}

	keyList := jwks["keys"].([]map[string]interface{})
	for _, k := range keys {
		if !k.IsActive && (k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt)) {
			continue // skip expired inactive keys
		}

		// Parse public key to extract n, e
		block, _ := pem.Decode([]byte(k.PublicKey))
		if block == nil {
			continue
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			continue
		}

		n := base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes())

		keyList = append(keyList, map[string]interface{}{
			"kty": "RSA",
			"use": "sig",
			"kid": k.KeyID,
			"alg": k.Algorithm,
			"n":   n,
			"e":   e,
		})
	}
	jwks["keys"] = keyList
	return jwks, nil
}

func (s *JWKSService) SignToken(ctx context.Context, claims jwt.Claims) (string, error) {
	activeKey, err := s.GetActiveKey(ctx)
	if err != nil {
		return "", err
	}
	if activeKey == nil {
		return "", ErrNoActiveSigningKey
	}

	// Parse private key
	block, _ := pem.Decode([]byte(activeKey.PrivateKey))
	if block == nil {
		return "", errors.New("invalid private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKey.KeyID
	return token.SignedString(privateKey)
}

func (s *JWKSService) VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// Parse token to get kid
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("missing kid in token header")
	}

	// Find signing key
	signingKey, err := s.keys.FindByKeyID(ctx, kid)
	if err != nil || signingKey == nil {
		return nil, errors.New("signing key not found")
	}

	// Parse public key
	block, _ := pem.Decode([]byte(signingKey.PublicKey))
	if block == nil {
		return nil, errors.New("invalid public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse and verify
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return pubKey, nil
	})
}

func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "kid_" + base64.URLEncoding.EncodeToString(b)[:16]
}

// StartKeyRotation starts a background goroutine to rotate keys periodically
func (s *JWKSService) StartKeyRotation(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := s.RotateKey(ctx); err != nil {
					// Log error but continue
					fmt.Printf("Key rotation failed: %v\n", err)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}