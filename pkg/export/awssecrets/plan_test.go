package awssecrets_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/export/awssecrets"
	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

func TestBuildDeterministic(t *testing.T) {
	first := secretmap.SecretMap{"DATABASE_URL": "postgres://host", "API_KEY": "秘密\x00\n"}
	second := secretmap.SecretMap{}
	second["API_KEY"] = first["API_KEY"]
	second["DATABASE_URL"] = first["DATABASE_URL"]
	want := awssecrets.Plan{Secrets: []awssecrets.Secret{{Name: "/myapp/API_KEY", Value: first["API_KEY"]}, {Name: "/myapp/DATABASE_URL", Value: first["DATABASE_URL"]}}}
	for i := 0; i < 20; i++ {
		for _, s := range []secretmap.SecretMap{first, second} {
			for _, prefix := range []string{"/myapp", "/myapp/"} {
				got, err := awssecrets.Build(s, awssecrets.Options{Prefix: prefix})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatal("non-deterministic mapping")
				}
			}
		}
	}
}

func TestBuildEmptyAndPrefix(t *testing.T) {
	for _, s := range []secretmap.SecretMap{nil, {}} {
		plan, err := awssecrets.Build(s, awssecrets.Options{})
		if err != nil || len(plan.Secrets) != 0 {
			t.Fatalf("empty: %v", err)
		}
	}
	for _, prefix := range []string{"", "/", "relative", "a_+=.@-"} {
		plan, err := awssecrets.Build(secretmap.SecretMap{"KEY": "value"}, awssecrets.Options{Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
		want := prefix
		if want != "" && !strings.HasSuffix(want, "/") {
			want += "/"
		}
		want += "KEY"
		if plan.Secrets[0].Name != want {
			t.Fatal("prefix changed")
		}
	}
}

func TestBuildRejectsInvalidProjection(t *testing.T) {
	for _, prefix := range []string{"bad prefix", "https://attacker.invalid", "../../foo", "a/../b", "a/./b", "a//b", "//", strings.Repeat("a", 513)} {
		if _, err := awssecrets.Build(nil, awssecrets.Options{Prefix: prefix}); !errors.Is(err, awssecrets.ErrInvalidPlan) {
			t.Fatalf("prefix accepted: %q", prefix)
		}
	}
	for _, key := range []string{"has space", "雪", "bad:key", strings.Repeat("a", 513)} {
		if _, err := awssecrets.Build(secretmap.SecretMap{key: "value"}, awssecrets.Options{}); !errors.Is(err, awssecrets.ErrInvalidPlan) {
			t.Fatalf("name accepted: %q", key)
		}
	}
	if _, err := awssecrets.Build(secretmap.SecretMap{"KEY": "v"}, awssecrets.Options{Prefix: strings.Repeat("p", 510)}); err == nil {
		t.Fatal("combined name too long accepted")
	}
	for _, value := range []string{"", strings.Repeat("a", 65537), strings.Repeat("雪", 21846)} {
		if _, err := awssecrets.Build(secretmap.SecretMap{"KEY": value}, awssecrets.Options{}); !errors.Is(err, awssecrets.ErrInvalidPlan) {
			t.Fatal("invalid value accepted")
		}
	}
	for _, value := range []string{strings.Repeat("a", 65536), strings.Repeat("雪", 21845)} {
		if _, err := awssecrets.Build(secretmap.SecretMap{strings.Repeat("a", 512): value}, awssecrets.Options{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := awssecrets.Build(secretmap.SecretMap{"": "value"}, awssecrets.Options{}); !errors.Is(err, secretmap.ErrInvalidSecretMap) {
		t.Fatal("invalid semantic map accepted")
	}
}

func TestPlanRejectsDuplicateNames(t *testing.T) {
	p := awssecrets.Plan{Secrets: []awssecrets.Secret{{Name: "same", Value: "a"}, {Name: "same", Value: "b"}}}
	if !errors.Is(p.Validate(), awssecrets.ErrInvalidPlan) {
		t.Fatal("duplicates accepted")
	}
}

// Artifact schema/content verification stays at the semantic boundary. The
// planner cannot accept metadata or trigger network I/O through its inputs.
func TestArtifactMetadataIgnoredAndSchemaRejected(t *testing.T) {
	secrets := secretmap.SecretMap{"API_KEY": "value"}
	metadata := artifact.Metadata{Name: "attacker-secret", Annotations: map[string]string{
		"aws.example/endpoint": "https://attacker.invalid", "aws.example/region": "attacker", "aws.example/account": "attacker", "aws.example/name": "attacker-secret", "enbu.net/path": "../../foo",
	}}
	a, data, err := secretmap.NewArtifact("019c6e27-e55b-73d1-87d8-4e01f1f75043", metadata, secrets)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := secretmap.ReadArtifact(context.Background(), a, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	got, err := awssecrets.Build(decoded, awssecrets.Options{Prefix: "/safe/"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := awssecrets.Build(secrets, awssecrets.Options{Prefix: "/safe/"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("metadata influenced plan")
	}
	a.Schema.Kind = "Opaque"
	if _, err := secretmap.ReadArtifact(context.Background(), a, bytes.NewReader(data)); !errors.Is(err, secretmap.ErrUnsupportedSchema) {
		t.Fatal("unsupported schema accepted")
	}
}
