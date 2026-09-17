package service_test

import (
	"testing"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/service"
)

func TestTokenServiceRoundTrip(t *testing.T) {
	tokens := service.NewTokenService("test-secret", time.Minute, time.Hour)

	access, err := tokens.GenerateAccessToken("user-1", "tenant-1", []string{"member"})
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	claims, err := tokens.Parse(access)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("claims.UserID = %q, want user-1", claims.UserID)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "member" {
		t.Fatalf("claims.Roles = %v, want [member]", claims.Roles)
	}
}

func TestTokenServiceRejectsForeignSecret(t *testing.T) {
	issuer := service.NewTokenService("secret-a", time.Minute, time.Hour)
	verifier := service.NewTokenService("secret-b", time.Minute, time.Hour)

	token, err := issuer.GenerateAccessToken("user-1", "tenant-1", []string{"member"})
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if _, err := verifier.Parse(token); err != service.ErrInvalidToken {
		t.Fatalf("Parse() error = %v, want ErrInvalidToken", err)
	}
}

func TestTokenServiceRejectsExpiredToken(t *testing.T) {
	tokens := service.NewTokenService("test-secret", -time.Minute, time.Hour)

	token, err := tokens.GenerateAccessToken("user-1", "tenant-1", []string{"member"})
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if _, err := tokens.Parse(token); err != service.ErrInvalidToken {
		t.Fatalf("Parse() error = %v, want ErrInvalidToken", err)
	}
}
