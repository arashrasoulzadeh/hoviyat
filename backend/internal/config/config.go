// Package config loads runtime configuration for the Hoviyat backend.
//
// The walking-skeleton stage (docs/TECHNICAL_DESIGN.md "Build sequence")
// reads plain environment variables with sane local defaults. Viper-based
// layered config (env + YAML + flags) is planned but not required until
// later stages need it.
package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPAddr        string
	DatabaseURL     string
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:        getEnv("HOVIYAT_HTTP_ADDR", ":8080"),
		DatabaseURL:     getEnv("HOVIYAT_DATABASE_URL", "postgres://hoviyat:hoviyat@localhost:5432/hoviyat?sslmode=disable"),
		JWTSecret:       getEnv("HOVIYAT_JWT_SECRET", "dev-secret-change-me"),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
