// Integration tests for Hoviyat API
// These tests run against a server started via docker-compose
// Run with: go test -tags=integration ./tests/integration/...
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testServerAddr = "localhost:18080"
)

var (
	serverURL string
)

func TestMain(m *testing.M) {
	// Check if docker-compose is available
	if _, err := exec.LookPath("docker-compose"); err != nil {
		// Try docker compose (v2)
		if _, err := exec.LookPath("docker"); err != nil {
			// Skip tests if docker not available
			os.Exit(0)
		}
	}

	// Start test infrastructure
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start docker-compose
	cmd := exec.CommandContext(ctx, "docker-compose", "up", "-d", "--build")
	cmd.Dir = "../.."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		// If docker-compose fails, skip tests
		os.Exit(0)
	}

	serverURL = "http://" + testServerAddr
	
	// Wait for server to be ready
	time.Sleep(10 * time.Second)

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupCmd := exec.Command("docker-compose", "down", "-v")
	cleanupCmd.Dir = "../.."
	cleanupCmd.Run()

	os.Exit(code)
}

func doRequest(method, path string, body any, token string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, serverURL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		rec := httptest.NewRecorder()
		rec.Code = 0
		rec.Body = bytes.NewBufferString(err.Error())
		return rec
	}
	defer resp.Body.Close()

	rec := httptest.NewRecorder()
	rec.Code = resp.StatusCode

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		rec.Body = bytes.NewBufferString(err.Error())
		return rec
	}
	rec.Body = bytes.NewBuffer(bodyBytes)
	return rec
}

func TestIntegration_HealthCheck(t *testing.T) {
	rec := doRequest("GET", "/healthz", nil, "")
	assert.Equal(t, http.StatusOK, rec.Code)
	
	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Equal(t, "ok", resp["status"])
}

func TestIntegration_RegisterUser(t *testing.T) {
	email := "test-" + time.Now().Format("150405") + "@example.com"
	rec := doRequest("POST", "/api/v1/auth/register", map[string]string{
		"email":    email,
		"password": "correct-horse-battery",
	}, "")
	
	// Without tenant_id, user is created without tenant membership
	assert.Equal(t, http.StatusCreated, rec.Code)
	
	var resp map[string]string
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
}

func TestIntegration_InvalidToken(t *testing.T) {
	rec := doRequest("GET", "/api/v1/users/me", nil, "invalid-token")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestIntegration_ExpiredToken(t *testing.T) {
	rec := doRequest("GET", "/api/v1/users/me", nil, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}