package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type AuthzCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewAuthzCache(redisURL string, ttl time.Duration) (*AuthzCache, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)
	return &AuthzCache{client: client, ttl: ttl}, nil
}

func (c *AuthzCache) Close() error {
	return c.client.Close()
}

func (c *AuthzCache) cacheKey(tenantID, userID, resourceType, resourceID, action string) string {
	return "authz:" + tenantID + ":" + userID + ":" + resourceType + ":" + resourceID + ":" + action
}

func (c *AuthzCache) Get(ctx context.Context, tenantID, userID, resourceType, resourceID, action string) (*AuthzResult, bool) {
	key := c.cacheKey(tenantID, userID, resourceType, resourceID, action)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, false
		}
		return nil, false
	}

	var result AuthzResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, false
	}
	return &result, true
}

func (c *AuthzCache) Set(ctx context.Context, tenantID, userID, resourceType, resourceID, action string, result *AuthzResult) error {
	key := c.cacheKey(tenantID, userID, resourceType, resourceID, action)
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, key, data, c.ttl).Err()
}

func (c *AuthzCache) Invalidate(ctx context.Context, tenantID, userID, resourceType, resourceID string) error {
	// Use pattern matching to invalidate all actions for this resource
	pattern := "authz:" + tenantID + ":" + userID + ":" + resourceType + ":" + resourceID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

func (c *AuthzCache) InvalidateBySubject(ctx context.Context, tenantID, subjectType, subjectID string) error {
	pattern := "authz:" + tenantID + ":" + subjectType + ":" + subjectID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

func (c *AuthzCache) InvalidateByResource(ctx context.Context, tenantID, resourceType, resourceID string) error {
	pattern := "authz:" + tenantID + ":*:" + resourceType + ":" + resourceID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

func (c *AuthzCache) InvalidateByTenant(ctx context.Context, tenantID string) error {
	pattern := "authz:" + tenantID + ":*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

func (c *AuthzCache) InvalidateAll(ctx context.Context) error {
	pattern := "authz:*"
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return c.client.Del(ctx, keys...).Err()
	}
	return nil
}

// PushInvalidation handles push-based cache invalidation via Redis pub/sub
type PushInvalidation struct {
	client    *redis.Client
	pubsub    *redis.PubSub
	handlers  map[string]func(string)
}

func NewPushInvalidation(redisURL string) (*PushInvalidation, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opt)
	pubsub := client.Subscribe(context.Background(), "authz:invalidate")
	return &PushInvalidation{
		client:   client,
		pubsub:   pubsub,
		handlers: make(map[string]func(string)),
	}, nil
}

func (pi *PushInvalidation) RegisterHandler(eventType string, handler func(string)) {
	pi.handlers[eventType] = handler
}

func (pi *PushInvalidation) Start(ctx context.Context) error {
	ch := pi.pubsub.Channel()
	for {
		select {
		case msg := <-ch:
			// Message format: eventType:payload
			// e.g., "acl_changed:tenant1:user123:document:doc456"
			parts := parseInvalidationMessage(msg.Payload)
			if len(parts) >= 2 {
				eventType := parts[0]
				payload := parts[1]
				if handler, ok := pi.handlers[eventType]; ok {
					handler(payload)
				}
			}
		case <-ctx.Done():
			return pi.pubsub.Close()
		}
	}
}

func (pi *PushInvalidation) Publish(ctx context.Context, eventType, payload string) error {
	return pi.client.Publish(ctx, "authz:invalidate", eventType+":"+payload).Err()
}

func (pi *PushInvalidation) Close() error {
	return pi.pubsub.Close()
}

func parseInvalidationMessage(msg string) []string {
	// Simple parser for "type:payload"
	for i := 0; i < len(msg); i++ {
		if msg[i] == ':' {
			return []string{msg[:i], msg[i+1:]}
		}
	}
	return []string{msg}
}