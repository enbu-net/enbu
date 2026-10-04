// Package awssecrets plans a SecretMap projection without SDK or network access.
package awssecrets

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

// AWS limits belong to this projection, never to the semantic schema.
// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html
const (
	MaxNameBytes  = 512
	MaxValueBytes = 65536
)

var (
	ErrInvalidPlan = errors.New("invalid AWS Secrets Manager export plan")
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
)

type Options struct{ Prefix string }
type Plan struct{ Secrets []Secret }
type Secret struct {
	Name  string
	Value string
}

// Build maps each semantic key to one AWS secret. Prefix is an explicit name
// namespace, with an optional leading/trailing slash. Nothing is path-cleaned
// or read from Artifact metadata: concatenation preserves distinct keys.
// Callers must use secretmap.ReadArtifact before passing untrusted artifacts.
func Build(secrets secretmap.SecretMap, options Options) (Plan, error) {
	if err := secrets.Validate(); err != nil {
		return Plan{}, err
	}
	prefix := options.Prefix
	if prefix != "" {
		if len(prefix) > MaxNameBytes || !namePattern.MatchString(prefix) {
			return Plan{}, fmt.Errorf("%w: invalid prefix", ErrInvalidPlan)
		}
		// Reject ambiguous namespaces rather than rewriting explicit configuration.
		for _, part := range strings.Split(strings.Trim(prefix, "/"), "/") {
			if part == "" && prefix != "/" || part == "." || part == ".." {
				return Plan{}, fmt.Errorf("%w: invalid prefix segment", ErrInvalidPlan)
			}
		}
		if strings.Contains(prefix, "//") {
			return Plan{}, fmt.Errorf("%w: invalid prefix segment", ErrInvalidPlan)
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
	}
	plan := Plan{Secrets: make([]Secret, 0, len(secrets))}
	for key, value := range secrets {
		plan.Secrets = append(plan.Secrets, Secret{Name: prefix + key, Value: value})
	}
	sort.Slice(plan.Secrets, func(i, j int) bool { return plan.Secrets[i].Name < plan.Secrets[j].Name })
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// Validate also protects application of caller-constructed or modified plans.
// Errors never include secret values.
func (p Plan) Validate() error {
	seen := make(map[string]struct{}, len(p.Secrets))
	for _, secret := range p.Secrets {
		if len(secret.Name) < 1 || len(secret.Name) > MaxNameBytes || !namePattern.MatchString(secret.Name) {
			return fmt.Errorf("%w: invalid secret name", ErrInvalidPlan)
		}
		if len(secret.Value) < 1 || len(secret.Value) > MaxValueBytes || !utf8.ValidString(secret.Value) {
			return fmt.Errorf("%w: value must contain 1-%d UTF-8 bytes", ErrInvalidPlan, MaxValueBytes)
		}
		if _, ok := seen[secret.Name]; ok {
			return fmt.Errorf("%w: duplicate secret name", ErrInvalidPlan)
		}
		seen[secret.Name] = struct{}{}
	}
	return nil
}
