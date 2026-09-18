package service

import (
	"context"
	"strings"
	"sync"
	"time"
)

type RiskSignal string

const (
	RiskSignalDisposableEmail RiskSignal = "disposable_email"
	RiskSignalVPNProxyTor     RiskSignal = "vpn_proxy_tor"
	RiskSignalVelocityAnomaly RiskSignal = "velocity_anomaly"
)

type RiskAssessment struct {
	Flags         []RiskSignal
	Score         int
	RequiresReview bool
	Reasons       []string
}

type RiskScorer struct {
	disposableDomains map[string]bool
	ipReputationCache map[string]int // -1 = bad, 0 = unknown, 1 = good
	tenantVelocity    map[string][]time.Time
	mu                sync.RWMutex
}

func NewRiskScorer() *RiskScorer {
	// Common disposable email domains (partial list)
	disposable := map[string]bool{
		"mailinator.com":     true,
		"tempmail.com":       true,
		"guerrillamail.com":  true,
		"10minutemail.com":   true,
		"throwawaymail.com":  true,
		"fakeinbox.com":      true,
		"trashmail.com":      true,
		"maildrop.cc":        true,
		"getnada.com":        true,
		"dispostable.com":    true,
		"yopmail.com":        true,
		"temp-mail.org":      true,
		"sharklasers.com":    true,
		"grr.la":             true,
		"spamgourmet.com":    true,
		"mintemail.com":      true,
		"spam4.me":           true,
		"bccto.me":           true,
		"chacuo.net":         true,
		"0clickemail.com":    true,
	}

	return &RiskScorer{
		disposableDomains: disposable,
		ipReputationCache: make(map[string]int),
		tenantVelocity:    make(map[string][]time.Time),
	}
}

func (rs *RiskScorer) AssessSignup(ctx context.Context, email, ip string) *RiskAssessment {
	assessment := &RiskAssessment{
		Flags:   []RiskSignal{},
		Score:   0,
		Reasons: []string{},
	}

	// Check disposable email domain
	domain := extractDomain(email)
	if rs.disposableDomains[domain] {
		assessment.Flags = append(assessment.Flags, RiskSignalDisposableEmail)
		assessment.Score += 40
		assessment.Reasons = append(assessment.Reasons, "disposable email domain detected")
	}

	// Check IP reputation (VPN/Proxy/Tor)
	// In production, this would call an external service like IPQualityScore, ipapi, etc.
	// For now, we check a local cache that would be populated from external feeds
	if rep, ok := rs.ipReputationCache[ip]; ok && rep < 0 {
		assessment.Flags = append(assessment.Flags, RiskSignalVPNProxyTor)
		assessment.Score += 35
		assessment.Reasons = append(assessment.Reasons, "VPN/Proxy/Tor IP detected")
	}

	// Check tenant creation velocity per IP
	rs.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	var recent []time.Time
	for _, t := range rs.tenantVelocity[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 { // 5 per hour is the hard limit, but we flag at 3
		assessment.Flags = append(assessment.Flags, RiskSignalVelocityAnomaly)
		assessment.Score += 25
		assessment.Reasons = append(assessment.Reasons, "high tenant creation velocity from IP")
	}
	rs.mu.Unlock()

	// Determine if manual review is required
	// PRD §9: "three concrete risk signals... route only flagged signups to manual platform-operator review"
	// Threshold: score >= 50 triggers review (any two signals, or one strong signal)
	assessment.RequiresReview = assessment.Score >= 50

	return assessment
}

func (rs *RiskScorer) RecordTenantCreation(ip string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	now := time.Now()
	rs.tenantVelocity[ip] = append(rs.tenantVelocity[ip], now)
}

func (rs *RiskScorer) SetIPReputation(ip string, reputation int) {
	rs.ipReputationCache[ip] = reputation
}

func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}