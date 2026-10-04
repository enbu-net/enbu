package aws_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/enbu-net/enbu/pkg/export/awssecrets"
	adapter "github.com/enbu-net/enbu/pkg/export/awssecrets/aws"
)

type fakeClient struct {
	create func(context.Context, *secretsmanager.CreateSecretInput) error
	put    func(context.Context, *secretsmanager.PutSecretValueInput) error
	calls  []string
}

func (f *fakeClient) CreateSecret(ctx context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	f.calls = append(f.calls, "create:"+sdkaws.ToString(in.Name))
	if f.create != nil {
		return nil, f.create(ctx, in)
	}
	return &secretsmanager.CreateSecretOutput{}, nil
}
func (f *fakeClient) PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.calls = append(f.calls, "put:"+sdkaws.ToString(in.SecretId))
	if f.put != nil {
		return nil, f.put(ctx, in)
	}
	return &secretsmanager.PutSecretValueOutput{}, nil
}

type contextKey struct{}

func TestApplyCreateAndUpdate(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKey{}, "marker")
	f := &fakeClient{}
	f.create = func(got context.Context, in *secretsmanager.CreateSecretInput) error {
		if got != ctx {
			t.Fatal("context changed")
		}
		if sdkaws.ToString(in.SecretString) != "秘密\x00\n" || in.SecretBinary != nil || len(in.Tags) != 0 || in.KmsKeyId != nil {
			t.Fatal("unexpected request projection")
		}
		if sdkaws.ToString(in.Name) == "/safe/existing" {
			return fmt.Errorf("wrapped: %w", &types.ResourceExistsException{})
		}
		return nil
	}
	f.put = func(got context.Context, in *secretsmanager.PutSecretValueInput) error {
		if got != ctx || sdkaws.ToString(in.SecretString) != "秘密\x00\n" || in.SecretBinary != nil {
			t.Fatal("unexpected update")
		}
		return nil
	}
	plan := awssecrets.Plan{Secrets: []awssecrets.Secret{{Name: "/safe/new", Value: "秘密\x00\n"}, {Name: "/safe/existing", Value: "秘密\x00\n"}}}
	if err := adapter.Apply(ctx, f, plan); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"create:/safe/new", "create:/safe/existing", "put:/safe/existing"}) {
		t.Fatal(f.calls)
	}
}

func TestApplyStopsOnFailure(t *testing.T) {
	denied := errors.New("access denied")
	for _, tt := range []struct {
		name      string
		createErr error
		putErr    error
		want      error
		calls     []string
	}{
		{"create", denied, nil, denied, []string{"create:first"}},
		{"message is not type", errors.New("ResourceExistsException"), nil, nil, []string{"create:first"}},
		{"update", &types.ResourceExistsException{}, denied, denied, []string{"create:first", "put:first"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeClient{create: func(context.Context, *secretsmanager.CreateSecretInput) error { return tt.createErr }, put: func(context.Context, *secretsmanager.PutSecretValueInput) error { return tt.putErr }}
			plan := awssecrets.Plan{Secrets: []awssecrets.Secret{{Name: "first", Value: "sensitive"}, {Name: "second", Value: "sensitive"}}}
			err := adapter.Apply(context.Background(), f, plan)
			want := tt.want
			if want == nil {
				want = tt.createErr
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v", err)
			}
			if !reflect.DeepEqual(f.calls, tt.calls) {
				t.Fatal(f.calls)
			}
		})
	}
}

func TestApplyValidatesBeforeSideEffects(t *testing.T) {
	for _, plan := range []awssecrets.Plan{
		{Secrets: []awssecrets.Secret{{Name: "valid", Value: "v"}, {Name: "bad name", Value: "v"}}},
		{Secrets: []awssecrets.Secret{{Name: "same", Value: "v"}, {Name: "same", Value: "v"}}},
		{Secrets: []awssecrets.Secret{{Name: "valid", Value: ""}}},
	} {
		f := &fakeClient{}
		if err := adapter.Apply(context.Background(), f, plan); !errors.Is(err, awssecrets.ErrInvalidPlan) {
			t.Fatal(err)
		}
		if len(f.calls) != 0 {
			t.Fatal("partial validation caused a write")
		}
	}
	f := &fakeClient{}
	if err := adapter.Apply(context.Background(), f, awssecrets.Plan{}); err != nil || len(f.calls) != 0 {
		t.Fatal("empty plan made requests")
	}
}

func TestApplyCancellation(t *testing.T) {
	for _, stage := range []string{"before", "after create", "before update"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeClient{create: func(context.Context, *secretsmanager.CreateSecretInput) error {
				cancel()
				if stage == "before update" {
					return &types.ResourceExistsException{}
				}
				return nil
			}}
			if stage == "before" {
				cancel()
			}
			plan := awssecrets.Plan{Secrets: []awssecrets.Secret{{Name: "first", Value: "v"}, {Name: "second", Value: "v"}}}
			if err := adapter.Apply(ctx, f, plan); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			want := 1
			if stage == "before" {
				want = 0
			}
			if len(f.calls) != want {
				t.Fatal(f.calls)
			}
		})
	}
}
