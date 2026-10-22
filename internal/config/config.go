package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the runtime configuration for the Utah Common AuthN/AuthZ service on GCP Cloud Run.
type Config struct {
	Port              string
	Environment       string
	DatabaseURL       string
	IssuerURL         string // Our service's canonical issuer URL (e.g. https://authz.water.utah.gov)
	SigningKeyPEM     string // Optional ECDSA P-256 private key PEM from GCP Secret Manager; auto-generated in dev if empty
	SigningKeyID      string // Key ID (kid) exposed in /.well-known/jwks.json
	AdminBootstrapKey string // Optional bootstrap API key for initial setup before UtahID admin login
	DefaultTokenTTL   time.Duration
}

// Load reads configuration from environment variables with sensible defaults for local and Cloud Run deployment.
func Load() (*Config, error) {
	port := getEnv("PORT", "8080")
	env := getEnv("ENVIRONMENT", "development")
	issuer := getEnv("AUTHZ_ISSUER_URL", "https://authz.utah.gov")
	kid := getEnv("AUTHZ_SIGNING_KEY_ID", "utah-zero-trust-key-2026-01")
	ttlSec, err := strconv.Atoi(getEnv("DEFAULT_TOKEN_TTL_SECONDS", "900"))
	if err != nil || ttlSec < 60 {
		ttlSec = 900
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Support Cloud Run standard Cloud SQL Unix socket or TCP env vars
		dbUser := getEnv("DB_USER", "postgres")
		dbPass := getEnv("DB_PASS", "postgres")
		dbName := getEnv("DB_NAME", "utah_authz")
		instanceConnName := os.Getenv("INSTANCE_UNIX_SOCKET") // e.g., /cloudsql/project:region:instance
		if instanceConnName != "" {
			dbURL = fmt.Sprintf("postgres://%s:%s@/%s?host=%s", dbUser, dbPass, dbName, instanceConnName)
		} else {
			dbHost := getEnv("DB_HOST", "localhost")
			dbPort := getEnv("DB_PORT", "5432")
			dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", dbUser, dbPass, dbHost, dbPort, dbName)
		}
	}

	return &Config{
		Port:              port,
		Environment:       env,
		DatabaseURL:       dbURL,
		IssuerURL:         issuer,
		SigningKeyPEM:     os.Getenv("AUTHZ_SIGNING_PRIVATE_KEY_PEM"),
		SigningKeyID:      kid,
		AdminBootstrapKey: os.Getenv("ADMIN_BOOTSTRAP_API_KEY"),
		DefaultTokenTTL:   time.Duration(ttlSec) * time.Second,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
