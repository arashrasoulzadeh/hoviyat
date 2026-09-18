package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

type ABACService struct {
	preparedQueries map[string]rego.PreparedEvalQuery
}

func NewABACService() *ABACService {
	return &ABACService{
		preparedQueries: make(map[string]rego.PreparedEvalQuery),
	}
}

func (s *ABACService) PrepareQuery(ctx context.Context, policyID, regoSource string) error {
	query, err := rego.New(
		rego.Query("data.hoviyat.authz.allow"),
		rego.Module("policy.rego", regoSource),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("prepare query: %w", err)
	}
	s.preparedQueries[policyID] = query
	return nil
}

func (s *ABACService) Evaluate(ctx context.Context, policyID string, input PolicyEvaluationInput) (bool, error) {
	query, ok := s.preparedQueries[policyID]
	if !ok {
		return false, fmt.Errorf("policy not prepared: %s", policyID)
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return false, fmt.Errorf("marshal input: %w", err)
	}

	results, err := query.Eval(ctx, rego.EvalInput(inputJSON))
	if err != nil {
		return false, fmt.Errorf("eval query: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}

	result, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, nil
	}

	return result, nil
}

func (s *ABACService) EvaluateAll(ctx context.Context, policyIDs []string, input PolicyEvaluationInput) (map[string]bool, error) {
	results := make(map[string]bool)
	for _, policyID := range policyIDs {
		allowed, err := s.Evaluate(ctx, policyID, input)
		if err != nil {
			return nil, err
		}
		results[policyID] = allowed
	}
	return results, nil
}