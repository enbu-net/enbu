// Package aws applies export plans through a caller-configured AWS SDK client.
package aws

import (
	"context"
	"errors"
	"fmt"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/enbu-net/enbu/pkg/export/awssecrets"
)

// Client exposes only the two operations needed by Apply. Credentials, region,
// endpoints, transport and SDK retry policy are configured by the caller.
type Client interface {
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

// Apply validates the entire plan before making any requests, then creates or
// updates secrets sequentially. It stops at the first failure; earlier writes
// may already be committed. It does not delete secrets or roll back writes.
// Reapplying produces the same current values, but can create new AWS versions.
func Apply(ctx context.Context, client Client, plan awssecrets.Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, secret := range plan.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: sdkaws.String(secret.Name), SecretString: sdkaws.String(secret.Value)})
		if err == nil {
			continue
		}
		var exists *types.ResourceExistsException
		// Using the create response avoids a Describe/Create race and extra API.
		if !errors.As(err, &exists) {
			return fmt.Errorf("create secret at index %d: %w", i, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err = client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: sdkaws.String(secret.Name), SecretString: sdkaws.String(secret.Value)})
		if err != nil {
			return fmt.Errorf("update secret at index %d: %w", i, err)
		}
	}
	return nil
}
