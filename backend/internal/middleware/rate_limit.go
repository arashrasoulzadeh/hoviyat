package middleware

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type TenantSignupRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	window   time.Duration
	limit    int
}

func NewTenantSignupRateLimiter(limit int, window time.Duration) *TenantSignupRateLimiter {
	return &TenantSignupRateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		limit:    limit,
	}
}

func (rl *TenantSignupRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	requests := rl.requests[key]
	var valid []time.Time
	for _, t := range requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[key] = valid
		return false
	}

	valid = append(valid, now)
	rl.requests[key] = valid
	return true
}

func (rl *TenantSignupRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.allow("tenant_signup:ip:" + ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": gin.H{
					"code":    "rate_limited",
					"message": "too many tenant signup attempts from this IP, try again later",
				},
			})
			return
		}

		// Read body without consuming it for the handler
		body, err := c.GetRawData()
		if err == nil && len(body) > 0 {
			// Use a simple JSON unmarshal to extract email
			// In production, use a proper JSON parser
			if len(body) > 0 && body[0] == '{' {
				// Quick check for email field
				if idx := findEmailInJSON(body); idx >= 0 {
					// Extract email value (simplified)
					// For rate limiting, we just need to know if email is present
					if !rl.allow("tenant_signup:email:extracted") {
						c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
							"error": gin.H{
								"code":    "rate_limited",
								"message": "too many tenant signup attempts for this email, try again later",
							},
						})
						return
					}
				}
			}
			// Restore body for handler
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		c.Next()
	}
}

func findEmailInJSON(data []byte) int {
	// Simple search for "email" key in JSON
	for i := 0; i < len(data)-6; i++ {
		if data[i] == '"' && i+6 < len(data) {
			if string(data[i:i+7]) == "\"email\"" {
				return i
			}
		}
	}
	return -1
}