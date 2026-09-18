package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/arashrasoulzadeh/hoviyat/backend/internal/domain"
)

var (
	ErrWebhookNotFound     = errors.New("webhook not found")
	ErrWebhookDeliveryFail = errors.New("webhook delivery failed")
)

type WebhookEventType string

const (
	WebhookEventUserCreated        WebhookEventType = "user.created"
	WebhookEventUserUpdated        WebhookEventType = "user.updated"
	WebhookEventUserDeleted        WebhookEventType = "user.deleted"
	WebhookEventUserLogin          WebhookEventType = "user.login"
	WebhookEventUserLogout         WebhookEventType = "user.logout"
	WebhookEventUserLoginFailed    WebhookEventType = "user.login_failed"
	WebhookEventTokenIssued        WebhookEventType = "token.issued"
	WebhookEventTokenRevoked       WebhookEventType = "token.revoked"
	WebhookEventTokenRefreshed     WebhookEventType = "token.refreshed"
	WebhookEventRoleAssigned       WebhookEventType = "role.assigned"
	WebhookEventRoleRevoked        WebhookEventType = "role.revoked"
	WebhookEventPermissionGranted  WebhookEventType = "permission.granted"
	WebhookEventPermissionRevoked  WebhookEventType = "permission.revoked"
	WebhookEventPolicyCreated      WebhookEventType = "policy.created"
	WebhookEventPolicyUpdated      WebhookEventType = "policy.updated"
	WebhookEventPolicyDeleted      WebhookEventType = "policy.deleted"
	WebhookEventPolicyActivated    WebhookEventType = "policy.activated"
	WebhookEventACLGranted         WebhookEventType = "acl.granted"
	WebhookEventACLRevoked         WebhookEventType = "acl.revoked"
	WebhookEventTenantCreated      WebhookEventType = "tenant.created"
	WebhookEventTenantUpdated      WebhookEventType = "tenant.updated"
	WebhookEventTenantDeleted      WebhookEventType = "tenant.deleted"
	WebhookEventTeamCreated        WebhookEventType = "team.created"
	WebhookEventTeamUpdated        WebhookEventType = "team.updated"
	WebhookEventTeamDeleted        WebhookEventType = "team.deleted"
	WebhookEventMemberAdded        WebhookEventType = "member.added"
	WebhookEventMemberRemoved      WebhookEventType = "member.removed"
	WebhookEventClientRegistered   WebhookEventType = "client.registered"
	WebhookEventClientUpdated      WebhookEventType = "client.updated"
	WebhookEventClientDeleted      WebhookEventType = "client.deleted"
	WebhookEventConsentGranted     WebhookEventType = "consent.granted"
	WebhookEventConsentRevoked     WebhookEventType = "consent.revoked"
	WebhookEventDataExported       WebhookEventType = "data.exported"
	WebhookEventDataErased         WebhookEventType = "data.erased"
	WebhookEventMFAEnrolled        WebhookEventType = "mfa.enrolled"
	WebhookEventMFARevoked         WebhookEventType = "mfa.revoked"
	WebhookEventPasswordChanged    WebhookEventType = "password.changed"
	WebhookEventPasswordReset      WebhookEventType = "password.reset"
	WebhookEventEmailVerified      WebhookEventType = "email.verified"
	WebhookEventImpersonationStart WebhookEventType = "impersonation.start"
	WebhookEventImpersonationEnd   WebhookEventType = "impersonation.end"
)

type Webhook struct {
	ID           string
	TenantID     string
	Name         string
	URL          string
	Secret       string // HMAC secret for payload signing
	Events       []WebhookEventType
	Enabled      bool
	RetryPolicy  *RetryPolicy
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RetryPolicy struct {
	MaxRetries      int           // Default: 3
	InitialInterval time.Duration // Default: 1 minute
	MaxInterval     time.Duration // Default: 1 hour
	Multiplier      float64       // Default: 2.0 (exponential backoff)
}

type WebhookDelivery struct {
	ID          string
	WebhookID   string
	EventType   WebhookEventType
	Payload     map[string]any
	Attempt     int
	StatusCode  int
	Response    string
	Error       string
	NextRetry   *time.Time
	CreatedAt   time.Time
	CompletedAt *time.Time
}

type WebhookRepository interface {
	Create(ctx context.Context, webhook *Webhook) error
	FindByID(ctx context.Context, id string) (*Webhook, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*Webhook, error)
	FindByTenantAndEvent(ctx context.Context, tenantID string, eventType WebhookEventType) ([]*Webhook, error)
	Update(ctx context.Context, webhook *Webhook) error
	Delete(ctx context.Context, id string) error
}

type WebhookDeliveryRepository interface {
	Create(ctx context.Context, delivery *WebhookDelivery) error
	FindByID(ctx context.Context, id string) (*WebhookDelivery, error)
	FindPending(ctx context.Context, before time.Time) ([]*WebhookDelivery, error)
	Update(ctx context.Context, delivery *WebhookDelivery) error
}

type WebhookService struct {
	webhooks    WebhookRepository
	deliveries  WebhookDeliveryRepository
	httpClient  *http.Client
}

func NewWebhookService(
	webhooks WebhookRepository,
	deliveries WebhookDeliveryRepository,
) *WebhookService {
	return &WebhookService{
		webhooks:   webhooks,
		deliveries: deliveries,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type RegisterWebhookRequest struct {
	Name       string             `json:"name" binding:"required"`
	URL        string             `json:"url" binding:"required,url"`
	Secret     string             `json:"secret"`
	Events     []WebhookEventType `json:"events" binding:"required,min=1"`
	RetryPolicy *RetryPolicy      `json:"retry_policy"`
}

type WebhookResponse struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	URL         string             `json:"url"`
	Events      []WebhookEventType `json:"events"`
	Enabled     bool               `json:"enabled"`
	RetryPolicy *RetryPolicy       `json:"retry_policy"`
	CreatedAt   time.Time          `json:"created_at"`
}

func toWebhookResponse(w *Webhook) WebhookResponse {
	return WebhookResponse{
		ID:          w.ID,
		Name:        w.Name,
		URL:         w.URL,
		Events:      w.Events,
		Enabled:     w.Enabled,
		RetryPolicy: w.RetryPolicy,
		CreatedAt:   w.CreatedAt,
	}
}

func (s *WebhookService) Register(ctx context.Context, tenantID, userID string, req RegisterWebhookRequest) (*WebhookResponse, error) {
	if req.Secret == "" {
		req.Secret = generateSecret()
	}

	retryPolicy := req.RetryPolicy
	if retryPolicy == nil {
		retryPolicy = &RetryPolicy{
			MaxRetries:      3,
			InitialInterval: time.Minute,
			MaxInterval:     time.Hour,
			Multiplier:      2.0,
		}
	}

	webhook := &Webhook{
		TenantID:    tenantID,
		Name:        req.Name,
		URL:         req.URL,
		Secret:      req.Secret,
		Events:      req.Events,
		Enabled:     true,
		RetryPolicy: retryPolicy,
	}

	if err := s.webhooks.Create(ctx, webhook); err != nil {
		return nil, err
	}

	resp := toWebhookResponse(webhook)
	return &resp, nil
}

func (s *WebhookService) Get(ctx context.Context, id string) (*WebhookResponse, error) {
	webhook, err := s.webhooks.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrWebhookNotFound) {
			return nil, ErrWebhookNotFound
		}
		return nil, err
	}
	resp := toWebhookResponse(webhook)
	return &resp, nil
}

func (s *WebhookService) List(ctx context.Context, tenantID string) ([]WebhookResponse, error) {
	webhooks, err := s.webhooks.FindByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	resp := make([]WebhookResponse, len(webhooks))
	for i, w := range webhooks {
		resp[i] = toWebhookResponse(w)
	}
	return resp, nil
}

func (s *WebhookService) Update(ctx context.Context, id string, updates map[string]any) (*WebhookResponse, error) {
	webhook, err := s.webhooks.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if name, ok := updates["name"].(string); ok {
		webhook.Name = name
	}
	if url, ok := updates["url"].(string); ok {
		webhook.URL = url
	}
	if secret, ok := updates["secret"].(string); ok {
		webhook.Secret = secret
	}
	if events, ok := updates["events"].([]WebhookEventType); ok {
		webhook.Events = events
	}
	if enabled, ok := updates["enabled"].(bool); ok {
		webhook.Enabled = enabled
	}
	if retryPolicy, ok := updates["retry_policy"].(*RetryPolicy); ok {
		webhook.RetryPolicy = retryPolicy
	}

	if err := s.webhooks.Update(ctx, webhook); err != nil {
		return nil, err
	}
	resp := toWebhookResponse(webhook)
	return &resp, nil
}

func (s *WebhookService) Delete(ctx context.Context, id string) error {
	return s.webhooks.Delete(ctx, id)
}

func (s *WebhookService) Dispatch(ctx context.Context, tenantID string, eventType WebhookEventType, payload map[string]any) error {
	webhooks, err := s.webhooks.FindByTenantAndEvent(ctx, tenantID, eventType)
	if err != nil {
		return err
	}

	for _, webhook := range webhooks {
		if !webhook.Enabled {
			continue
		}
		go s.deliver(ctx, webhook, eventType, payload)
	}
	return nil
}

func (s *WebhookService) deliver(ctx context.Context, webhook *Webhook, eventType WebhookEventType, payload map[string]any) {
	delivery := &WebhookDelivery{
		WebhookID:  webhook.ID,
		EventType:  eventType,
		Payload:    payload,
		Attempt:    0,
		CreatedAt:  time.Now(),
	}

	payloadBytes, _ := json.Marshal(map[string]any{
		"event_type": string(eventType),
		"timestamp":  time.Now().Format(time.RFC3339),
		"payload":    payload,
	})

	signature := signPayload(webhook.Secret, payloadBytes)

	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hoviyat-Signature", signature)
	req.Header.Set("X-Hoviyat-Event", string(eventType))
	req.Header.Set("X-Hoviyat-Delivery", delivery.ID)
	req.Body = &nopCloser{bytes.NewReader(payloadBytes)}

	resp, err := s.httpClient.Do(req)
	delivery.Attempt = 1
	delivery.CreatedAt = time.Now()

	if err != nil {
		delivery.Error = err.Error()
		delivery.StatusCode = 0
		s.scheduleRetry(ctx, delivery, webhook)
		return
	}
	defer resp.Body.Close()

	delivery.StatusCode = resp.StatusCode

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		now := time.Now()
		delivery.CompletedAt = &now
	} else {
		delivery.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		s.scheduleRetry(ctx, delivery, webhook)
	}
}

func (s *WebhookService) scheduleRetry(ctx context.Context, delivery *WebhookDelivery, webhook *Webhook) {
	if delivery.Attempt >= webhook.RetryPolicy.MaxRetries {
		return // Max retries reached
	}

	interval := webhook.RetryPolicy.InitialInterval
	for i := 1; i < delivery.Attempt; i++ {
		interval = time.Duration(float64(interval) * webhook.RetryPolicy.Multiplier)
		if interval > webhook.RetryPolicy.MaxInterval {
			interval = webhook.RetryPolicy.MaxInterval
			break
		}
	}

	nextRetry := time.Now().Add(interval)
	delivery.NextRetry = &nextRetry

	// In real implementation, would use a job queue or scheduler
	// For now, just log
	fmt.Printf("Scheduled retry for delivery %s at %v\n", delivery.ID, nextRetry)
}

func signPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func generateSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// nopCloser wraps an io.Reader to implement io.ReadCloser
type nopCloser struct {
	*bytes.Reader
}

func (nopCloser) Close() error { return nil }