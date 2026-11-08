package storage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Fixed keys and verification time keep certificate validity independent of
// the machine's wall clock. TLS handshakes remain real native adapter tests.
func boundaryCertificates(t *testing.T, fault string) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	start, end := time.Unix(1577836800, 0), time.Unix(3155760000, 0)
	key := func(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)) }
	issue := func(template, parent *x509.Certificate, public ed25519.PublicKey, signer ed25519.PrivateKey) []byte {
		t.Helper()
		der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 4096)), template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	caKey := key(1)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trusted fixture CA"}, NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER := issue(caTemplate, caTemplate, caKey.Public().(ed25519.PublicKey), caKey)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leafKey := key(2)
	leaf := x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	valid := tls.Certificate{Certificate: [][]byte{issue(&leaf, ca, leafKey.Public().(ed25519.PublicKey), caKey)}, PrivateKey: leafKey}
	leaf.SerialNumber = big.NewInt(3)
	signer, parent := caKey, ca
	switch fault {
	case "unknown-authority":
		signer = key(3)
		foreign := *caTemplate
		foreign.Subject = pkix.Name{CommonName: "foreign fixture CA"}
		foreignDER := issue(&foreign, &foreign, signer.Public().(ed25519.PublicKey), signer)
		parent, err = x509.ParseCertificate(foreignDER)
		if err != nil {
			t.Fatal(err)
		}
	case "wrong-host":
		leaf.IPAddresses = nil
		leaf.DNSNames = []string{"unrelated.invalid"}
	case "expired":
		leaf.NotAfter = time.Unix(1609459200, 0)
	case "not-yet-valid":
		leaf.NotBefore = time.Unix(2524608000, 0)
	default:
		t.Fatalf("unknown certificate fault %q", fault)
	}
	bad := tls.Certificate{Certificate: [][]byte{issue(&leaf, parent, leafKey.Public().(ed25519.PublicKey), signer)}, PrivateKey: leafKey}
	return valid, bad, roots
}

func TestRemoteTLSCertificateBoundaries(t *testing.T) {
	for _, backend := range []string{"oci", "s3"} {
		for _, fault := range []string{"unknown-authority", "wrong-host", "expired", "not-yet-valid"} {
			for _, operation := range []string{"discover", "head", "blob"} {
				t.Run(backend+"/"+fault+"/"+operation, func(t *testing.T) {
					valid, bad, roots := boundaryCertificates(t, fault)
					var active atomic.Pointer[tls.Certificate]
					active.Store(&valid)
					var requests atomic.Int32
					object := Object{Kind: KindState, Scope: StateScope("team", "default"), Head: []byte("signed-header-fixture"), Payload: []byte("encrypted-payload-fixture")}
					object.Rev = digest.FromBytes(object.Head)
					_, manifest, desc, err := manifestFor(object)
					if err != nil {
						t.Fatal(err)
					}
					name, err := Name(object.Kind, object.Scope, object.Rev)
					if err != nil {
						t.Fatal(err)
					}
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if backend == "s3" {
							if r.URL.Query().Get("list-type") != "" {
								w.Header().Set("Content-Type", "application/xml")
								_, _ = fmt.Fprintf(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>team</Name><IsTruncated>false</IsTruncated><Contents><Key>secrets/revisions/%s</Key></Contents></ListBucketResult>`, name)
								return
							}
							w.Header().Set("Content-Type", "application/octet-stream")
							w.Header().Set("ETag", `"fixture-etag"`)
							w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
							http.ServeContent(w, r, "fixture", time.Time{}, bytes.NewReader(frame(object)))
							return
						}
						var data []byte
						var media, dgst string
						switch {
						case strings.HasSuffix(r.URL.Path, "/tags/list"):
							w.Header().Set("Content-Type", "application/json")
							_, _ = fmt.Fprintf(w, `{"name":"team/secrets","tags":[%q]}`, name)
							return
						case strings.Contains(r.URL.Path, "/manifests/"):
							data, media, dgst = manifest, ocispec.MediaTypeImageManifest, desc.Digest.String()
						case strings.HasSuffix(r.URL.Path, "/blobs/"+object.Rev.String()):
							data, media, dgst = object.Head, "application/octet-stream", object.Rev.String()
						case strings.HasSuffix(r.URL.Path, "/blobs/"+digest.FromBytes(object.Payload).String()):
							data, media, dgst = object.Payload, "application/octet-stream", digest.FromBytes(object.Payload).String()
						default:
							http.NotFound(w, r)
							return
						}
						w.Header().Set("Content-Type", media)
						w.Header().Set("Content-Length", strconv.Itoa(len(data)))
						w.Header().Set("Docker-Content-Digest", dgst)
						if r.Method != http.MethodHead {
							_, _ = w.Write(data)
						}
					}))
					server.Config.ErrorLog = log.New(io.Discard, "", 0)
					server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
						return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*active.Load()}}, nil
					}}
					server.StartTLS()
					defer server.Close()
					transport := http.DefaultTransport.(*http.Transport).Clone()
					transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Time: func() time.Time { return time.Unix(1767225600, 0) }}
					defer transport.CloseIdleConnections()
					endpoint := strings.TrimPrefix(server.URL, "https://")
					var store Store
					if backend == "oci" {
						store, err = NewOCI(endpoint+"/team/secrets", func(context.Context, string) (auth.Credential, error) { return auth.EmptyCredential, nil }, false)
						if err == nil {
							withHTTPClient(store, &http.Client{Transport: transport})
						}
					} else {
						var client *minio.Client
						// Certificate rejection needs one attempt, with no SDK
						// jitter/backoff. Recovery is an explicit later request.
						client, err = minio.New(endpoint, &minio.Options{Region: "us-east-1", Secure: true, MaxRetries: 1, BucketLookup: minio.BucketLookupPath, Transport: transport, Creds: credentials.NewStaticV4("fixture-access", "fixture-secret", "")})
						if err == nil {
							store = NewS3(client, "team", "secrets")
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					attempt := func() error {
						switch operation {
						case "discover":
							refs, err := store.Discover(t.Context(), object.Kind, object.Scope)
							if err != nil {
								return err
							}
							if !reflect.DeepEqual(refs, []digest.Digest{object.Rev}) {
								return fmt.Errorf("unexpected revisions: %v", refs)
							}
						case "head":
							head, err := store.FetchHead(t.Context(), object.Kind, object.Scope, object.Rev)
							if err != nil {
								return err
							}
							if !bytes.Equal(head, object.Head) {
								return fmt.Errorf("wrong header")
							}
						case "blob":
							reader, err := store.OpenPayload(t.Context(), object.Kind, object.Scope, object.Rev)
							if err != nil {
								return err
							}
							defer func() { _ = reader.Close() }()
							payload, err := io.ReadAll(reader)
							if err != nil {
								return err
							}
							if !bytes.Equal(payload, object.Payload) {
								return fmt.Errorf("wrong payload")
							}
						}
						return nil
					}
					if err := attempt(); err != nil {
						t.Fatalf("valid certificate control: %v", err)
					}
					transport.CloseIdleConnections()
					before := requests.Load()
					active.Store(&bad)
					err = attempt()
					var verification *tls.CertificateVerificationError
					if !errors.As(err, &verification) {
						t.Fatalf("expected certificate verification failure: %v", err)
					}
					switch fault {
					case "unknown-authority":
						var cause x509.UnknownAuthorityError
						if !errors.As(err, &cause) {
							t.Fatalf("wrong certificate failure: %v", err)
						}
					case "wrong-host":
						var cause x509.HostnameError
						if !errors.As(err, &cause) {
							t.Fatalf("wrong certificate failure: %v", err)
						}
					default:
						var cause x509.CertificateInvalidError
						if !errors.As(err, &cause) || cause.Reason != x509.Expired {
							t.Fatalf("wrong certificate validity failure: %v", err)
						}
					}
					if requests.Load() != before {
						t.Fatal("unverified TLS peer received an HTTP request")
					}
					active.Store(&valid)
					if err := attempt(); err != nil {
						t.Fatalf("same-client certificate recovery: %v", err)
					}
					if requests.Load() <= before {
						t.Fatal("recovery did not reach the verified peer")
					}
				})
			}
		}
	}
}
