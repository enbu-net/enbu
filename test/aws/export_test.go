//go:build awse2e

package awse2e_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/export/awssecrets"
	adapter "github.com/enbu-net/enbu/pkg/export/awssecrets/aws"
	"github.com/enbu-net/enbu/pkg/schema/secretmap"
)

// The harness rejects any SDK request that escapes its explicit endpoint or
// signing region, even when malicious metadata supplies plausible alternatives.
type guardedTransport struct {
	endpoint *url.URL
	calls    atomic.Int64
}

func (g *guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != g.endpoint.Scheme || r.URL.Host != g.endpoint.Host {
		return nil, errors.New("request escaped configured endpoint")
	}
	if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/secretsmanager/aws4_request") {
		return nil, errors.New("request escaped configured signing region")
	}
	g.calls.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func TestExportToKumo(t *testing.T) {
	endpoint := os.Getenv("ENBU_TEST_KUMO_ENDPOINT")
	if endpoint == "" {
		t.Fatal("ENBU_TEST_KUMO_ENDPOINT is required; run task export/aws/test/e2e")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		t.Fatal("Kumo test endpoint must be local HTTP")
	}
	var attackerCalls atomic.Int64
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerCalls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer attacker.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	guard := &guardedTransport{endpoint: parsed}
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		config.WithHTTPClient(&http.Client{Transport: guard, Timeout: 5 * time.Second}),
		config.WithRetryMaxAttempts(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.BaseEndpoint = sdkaws.String(endpoint) })
	metadata := artifact.Metadata{Name: "attacker-secret", Annotations: map[string]string{
		"aws.example/endpoint": attacker.URL, "aws.example/region": "attacker", "aws.example/account": "attacker", "aws.example/name": "attacker-secret", "enbu.net/path": "../../foo",
	}}
	values := secretmap.SecretMap{"DATABASE_URL": "postgres://localhost/example", "API_KEY": "foo"}
	for _, value := range []string{"foo", "bar", "bar", "foo"} {
		values["API_KEY"] = value
		a, data, err := secretmap.NewArtifact("019c6e27-e55b-73d1-87d8-4e01f1f75043", metadata, values)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := secretmap.ReadArtifact(ctx, a, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		plan, err := awssecrets.Build(decoded, awssecrets.Options{Prefix: "/safe/"})
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Apply(ctx, client, plan); err != nil {
			t.Fatal(err)
		}
		for key, want := range values {
			got, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: sdkaws.String("/safe/" + key)})
			if err != nil {
				t.Fatal(err)
			}
			if got.SecretString == nil || *got.SecretString != want {
				t.Fatal("exported value differs")
			}
		}
	}
	// The isolated Compose instance must contain only the explicitly planned names.
	var names []string
	pager := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range page.SecretList {
			names = append(names, sdkaws.ToString(secret.Name))
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"/safe/API_KEY", "/safe/DATABASE_URL"}) {
		t.Fatal("unexpected secret destinations")
	}
	if attackerCalls.Load() != 0 {
		t.Fatal("metadata caused attacker endpoint requests")
	}
	if guard.calls.Load() == 0 {
		t.Fatal("no real SDK requests reached Kumo")
	}
	t.Logf("verified %d SDK requests against explicit Kumo endpoint", guard.calls.Load())
}
