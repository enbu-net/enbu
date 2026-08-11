package plugin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

var (
	minimalTransform = []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x12, 0x01, 0x0e, 'e', 'n', 'b', 'u', '_', 't', 'r', 'a', 'n', 's', 'f', 'o', 'r', 'm', 0x00, 0x00,
		0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0b,
	}
	testNamespace = TypeNamespace{Group: "scanner.example.com", Version: "v1"}
	testType      = artifact.TypeRef{Group: testNamespace.Group, Version: testNamespace.Version, Kind: "FindingSet"}
)

type packageFixture struct {
	pkg      Package
	grant    TrustGrant
	verified VerifiedPackage
	public   ed25519.PublicKey
	private  ed25519.PrivateKey
}

func newPackageFixture(t *testing.T, module []byte, namespaces []TypeNamespace) packageFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := NewPackage(module, "issuer.example.com", "plugin:firmware-scanner", namespaces)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = SignPackage(pkg, private)
	if err != nil {
		t.Fatal(err)
	}
	packageDigest, err := PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewTrustGrant(
		TrustScopeLocal,
		packageDigest,
		pkg.Issuer,
		pkg.Subject,
		pkg.OutputNamespaces,
		public,
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPackage(pkg, grant)
	if err != nil {
		t.Fatal(err)
	}
	return packageFixture{pkg: pkg, grant: grant, verified: verified, public: public, private: private}
}

func TestVerifyPackageRequiresSignatureAndExactTrustGrant(t *testing.T) {
	fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})

	if fixture.verified.Issuer() != fixture.pkg.Issuer || fixture.verified.Subject() != fixture.pkg.Subject {
		t.Fatalf("verified identity = %q/%q", fixture.verified.Issuer(), fixture.verified.Subject())
	}
	if fixture.verified.ModuleDigest() != fixture.pkg.ModuleDigest || fixture.verified.Digest() != fixture.grant.PackageDigest {
		t.Fatal("verified digests do not match the signed package")
	}

	t.Run("package digest", func(t *testing.T) {
		grant := fixture.grant
		grant.PackageDigest = digest.FromString("another package")
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrUntrustedPackage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("issuer", func(t *testing.T) {
		grant := fixture.grant
		grant.Issuer = "other.example.com"
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrUntrustedPackage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("subject", func(t *testing.T) {
		grant := fixture.grant
		grant.Subject = "plugin:other"
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrUntrustedPackage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("output namespaces", func(t *testing.T) {
		grant := fixture.grant
		grant.AllowedOutputNamespaces = []TypeNamespace{{Group: "other.example.com", Version: "v1"}}
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrUntrustedPackage) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("trusted key", func(t *testing.T) {
		otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		grant := fixture.grant
		grant.SigningKey = otherPublic
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrInvalidPackage) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestVerifyPackageRejectsTamperingAndUnknownContracts(t *testing.T) {
	fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})

	tests := map[string]func(*Package){
		"module": func(pkg *Package) {
			pkg.Module = append([]byte(nil), pkg.Module...)
			pkg.Module[len(pkg.Module)-1]++
		},
		"module digest": func(pkg *Package) { pkg.ModuleDigest = digest.FromString("tampered") },
		"issuer":        func(pkg *Package) { pkg.Issuer = "attacker.example.com" },
		"subject":       func(pkg *Package) { pkg.Subject = "plugin:attacker" },
		"outputs": func(pkg *Package) {
			pkg.OutputNamespaces = []TypeNamespace{{Group: "attacker.example.com", Version: "v1"}}
		},
		"signature": func(pkg *Package) {
			pkg.Signature = append([]byte(nil), pkg.Signature...)
			pkg.Signature[0]++
		},
		"unknown major": func(pkg *Package) { pkg.APIVersion = "plugins.enbu.net/v2" },
		"unknown type":  func(pkg *Package) { pkg.Kind = "OtherPackage" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pkg := clonePackage(fixture.pkg)
			mutate(&pkg)
			if _, err := VerifyPackage(pkg, fixture.grant); !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	t.Run("unknown grant major", func(t *testing.T) {
		grant := fixture.grant
		grant.APIVersion = "plugins.enbu.net/v2"
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrInvalidTrustGrant) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unknown grant type", func(t *testing.T) {
		grant := fixture.grant
		grant.Kind = "OtherGrant"
		if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrInvalidTrustGrant) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestPackageRejectsReservedDuplicateAndOverbroadNamespaces(t *testing.T) {
	tests := map[string][]TypeNamespace{
		"reserved host namespace": {{Group: "schemas.enbu.net", Version: "v1alpha1"}},
		"duplicate":               {testNamespace, testNamespace},
		"overbroad":               {{Group: "com", Version: "v1"}},
	}
	for name, namespaces := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewPackage(minimalTransform, "issuer.example.com", "plugin:test", namespaces)
			if !errors.Is(err, ErrInvalidPackage) {
				t.Fatalf("error = %v", err)
			}
			if name == "reserved host namespace" && !errors.Is(err, artifact.ErrReservedNamespace) {
				t.Fatalf("reserved namespace cause was lost: %v", err)
			}
		})
	}

	fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
	grant := fixture.grant
	grant.AllowedOutputNamespaces = []TypeNamespace{testNamespace, testNamespace}
	if _, err := VerifyPackage(fixture.pkg, grant); !errors.Is(err, ErrInvalidTrustGrant) {
		t.Fatalf("duplicate grant namespace error = %v", err)
	}
}

func TestNewPackageAndTrustGrantCanonicalizeNamespaces(t *testing.T) {
	second := TypeNamespace{Group: "z.example.com", Version: "v1beta1"}
	pkg, err := NewPackage(minimalTransform, "issuer.example.com", "plugin:test", []TypeNamespace{second, testNamespace})
	if err != nil {
		t.Fatal(err)
	}
	if pkg.OutputNamespaces[0] != testNamespace || pkg.OutputNamespaces[1] != second {
		t.Fatalf("outputs = %#v", pkg.OutputNamespaces)
	}

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewTrustGrant(
		TrustScopeOrganization,
		digest.FromString("package"),
		pkg.Issuer,
		pkg.Subject,
		[]TypeNamespace{second, testNamespace},
		public,
	)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Scope != TrustScopeOrganization || grant.AllowedOutputNamespaces[0] != testNamespace {
		t.Fatalf("grant = %#v", grant)
	}
}

func TestPackageAndTrustGrantCanonicalRoundTrip(t *testing.T) {
	fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
	encodedPackage, err := EncodePackage(fixture.pkg)
	if err != nil {
		t.Fatal(err)
	}
	decodedPackage, err := DecodePackage(encodedPackage)
	if err != nil {
		t.Fatal(err)
	}
	if decodedPackage.ModuleDigest != fixture.pkg.ModuleDigest || !bytes.Equal(decodedPackage.Signature, fixture.pkg.Signature) {
		t.Fatalf("decoded package = %#v", decodedPackage)
	}

	encodedGrant, err := EncodeTrustGrant(fixture.grant)
	if err != nil {
		t.Fatal(err)
	}
	decodedGrant, err := DecodeTrustGrant(encodedGrant)
	if err != nil {
		t.Fatal(err)
	}
	if decodedGrant.PackageDigest != fixture.grant.PackageDigest || !bytes.Equal(decodedGrant.SigningKey, fixture.grant.SigningKey) {
		t.Fatalf("decoded grant = %#v", decodedGrant)
	}

	if _, err := DecodePackage(append(encodedPackage, 0)); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("trailing package data error = %v", err)
	}
	if _, err := DecodeTrustGrant(append(encodedGrant, 0)); !errors.Is(err, ErrInvalidTrustGrant) {
		t.Fatalf("trailing grant data error = %v", err)
	}
}

func TestHostExecutesVerifiedPackageWithoutWASI(t *testing.T) {
	fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
	host, err := NewHost(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sink := newMemorySink()
	drafts, err := host.Execute(
		context.Background(),
		fixture.verified,
		[]Input{{Reader: readerAtString("input"), Size: 5}},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) != 0 || sink.count() != 0 {
		t.Fatalf("drafts = %#v, sink count = %d", drafts, sink.count())
	}
}

func TestHostStreamsOutputToObjectSink(t *testing.T) {
	payload := []byte("SSID=lab\nPASSWORD=secret\n")
	module := outputTransform("wifi-finding", testType.String(), payload, "enbu")
	fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
	host, err := NewHost(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sink := newMemorySink()
	drafts, err := host.Execute(
		context.Background(),
		fixture.verified,
		[]Input{{Reader: readerAtString("firmware"), Size: 8}},
		sink,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(drafts) != 1 {
		t.Fatalf("drafts = %#v", drafts)
	}
	draft := drafts[0]
	if draft.Type != testType || draft.Metadata.Name != "wifi-finding" {
		t.Fatalf("draft metadata = %#v", draft)
	}
	if draft.Object.MediaType != MediaTypeDraft || draft.Object.Size != int64(len(payload)) {
		t.Fatalf("descriptor = %#v", draft.Object)
	}
	if got := sink.object(draft.Object.Digest); !bytes.Equal(got, payload) {
		t.Fatalf("stored payload = %q", got)
	}
}

func TestHostRejectsUndeclaredOutputAndOutputLimitEvenWhenModuleIgnoresErrors(t *testing.T) {
	t.Run("undeclared output", func(t *testing.T) {
		module := outputTransform("draft", "other.example.com/v1/FindingSet", []byte("x"), "enbu")
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		host, err := NewHost(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host.Execute(context.Background(), fixture.verified, []Input{{Reader: readerAtString(""), Size: 0}}, newMemorySink()); !errors.Is(err, ErrExecution) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("aggregate output limit", func(t *testing.T) {
		module := outputTransform("draft", testType.String(), []byte("four"), "enbu")
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		limits := DefaultLimits()
		limits.MaxOutput = 3
		host, err := NewHost(limits)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host.Execute(context.Background(), fixture.verified, []Input{{Reader: readerAtString(""), Size: 0}}, newMemorySink()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestHostRejectsUnknownImportsBoundsAndInvalidSinkDescriptor(t *testing.T) {
	t.Run("WASI import", func(t *testing.T) {
		module := outputTransform("draft", testType.String(), []byte("x"), "wasi_snapshot_preview1")
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		host, err := NewHost(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host.Execute(context.Background(), fixture.verified, []Input{{Reader: readerAtString(""), Size: 0}}, newMemorySink()); !errors.Is(err, ErrUnknownImport) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("input bound", func(t *testing.T) {
		fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
		host, err := NewHost(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host.Execute(context.Background(), fixture.verified, []Input{{Reader: readerAtString(""), Size: MaxInputBytes + 1}}, newMemorySink()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("invalid sink descriptor", func(t *testing.T) {
		module := outputTransform("draft", testType.String(), []byte("x"), "enbu")
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		host, err := NewHost(DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		sink := newMemorySink()
		sink.invalidDescriptor = true
		if _, err := host.Execute(context.Background(), fixture.verified, []Input{{Reader: readerAtString(""), Size: 0}}, sink); !errors.Is(err, ErrExecution) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestNewHostEnforcesHardCeilings(t *testing.T) {
	memory := DefaultLimits()
	memory.MemoryPages = MaxMemoryPages + 1
	calls := DefaultLimits()
	calls.CallLimit = MaxCallLimit + 1
	input := DefaultLimits()
	input.MaxInput = MaxInputBytes + 1
	output := DefaultLimits()
	output.MaxOutput = MaxOutputBytes + 1
	zeroDuration := DefaultLimits()
	zeroDuration.Duration = 0
	negativeDuration := DefaultLimits()
	negativeDuration.Duration = -time.Nanosecond
	longDuration := DefaultLimits()
	longDuration.Duration = MaxDuration + time.Nanosecond
	tests := []Limits{memory, calls, input, output, zeroDuration, negativeDuration, longDuration}
	for index, limits := range tests {
		if _, err := NewHost(limits); !errors.Is(err, ErrLimit) {
			t.Fatalf("limits[%d] error = %v", index, err)
		}
	}
	if limits := DefaultLimits(); limits.Duration != DefaultDuration {
		t.Fatalf("default duration = %v, want %v", limits.Duration, DefaultDuration)
	}
}

func TestHostWallClockLimitStopsNoImportInfiniteLoop(t *testing.T) {
	t.Parallel()

	fixture := newPackageFixture(t, noImportInfiniteLoop(), []TypeNamespace{testNamespace})
	limits := DefaultLimits()
	limits.Duration = 100 * time.Millisecond
	host, err := NewHost(limits)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	started := time.Now()
	go func() {
		_, executeErr := host.Execute(
			context.Background(),
			fixture.verified,
			[]Input{{Reader: readerAtString("input"), Size: 5}},
			newMemorySink(),
		)
		result <- executeErr
	}()
	select {
	case executeErr := <-result:
		if !errors.Is(executeErr, ErrLimit) || !errors.Is(executeErr, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want wall-clock ErrLimit and DeadlineExceeded", executeErr)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("infinite guest stopped after %v", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no-import infinite-loop Wasm ignored the host-owned deadline")
	}
}

func TestHostEnforcesDenseInputHandlesAndAggregateBounds(t *testing.T) {
	host, err := NewHost(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("dense handle", func(t *testing.T) {
		module := inputLenProbe(1)
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		_, err := host.Execute(
			context.Background(), fixture.verified,
			[]Input{{Reader: readerAtString("x"), Size: 1}}, newMemorySink(),
		)
		if !errors.Is(err, ErrExecution) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("read range", func(t *testing.T) {
		module := readAtProbe(0, 1, 1)
		fixture := newPackageFixture(t, module, []TypeNamespace{testNamespace})
		_, err := host.Execute(
			context.Background(), fixture.verified,
			[]Input{{Reader: readerAtString("x"), Size: 1}}, newMemorySink(),
		)
		if !errors.Is(err, ErrExecution) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
		if _, err := host.Execute(context.Background(), fixture.verified, nil, newMemorySink()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("count", func(t *testing.T) {
		fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
		inputs := make([]Input, MaxInputs+1)
		if _, err := host.Execute(context.Background(), fixture.verified, inputs, newMemorySink()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("aggregate size", func(t *testing.T) {
		fixture := newPackageFixture(t, minimalTransform, []TypeNamespace{testNamespace})
		inputs := []Input{
			{Reader: readerAtString(""), Size: MaxInputBytes},
			{Reader: readerAtString(""), Size: 1},
		}
		if _, err := host.Execute(context.Background(), fixture.verified, inputs, newMemorySink()); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})
}

type readerAtString string

func (reader readerAtString) ReadAt(target []byte, offset int64) (int, error) {
	if offset >= int64(len(reader)) {
		return 0, io.EOF
	}
	count := copy(target, reader[offset:])
	if count < len(target) {
		return count, io.EOF
	}
	return count, nil
}

type memorySink struct {
	mu                sync.Mutex
	objects           map[digest.Digest][]byte
	invalidDescriptor bool
}

func newMemorySink() *memorySink {
	return &memorySink{objects: make(map[digest.Digest][]byte)}
}

func (sink *memorySink) Ingest(_ context.Context, mediaType string, reader io.Reader) (artifact.Descriptor, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxOutputBytes+1))
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := artifact.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	sink.mu.Lock()
	sink.objects[descriptor.Digest] = append([]byte(nil), data...)
	sink.mu.Unlock()
	if sink.invalidDescriptor {
		descriptor.Size++
	}
	return descriptor, nil
}

func (sink *memorySink) count() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.objects)
}

func (sink *memorySink) object(objectDigest digest.Digest) []byte {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]byte(nil), sink.objects[objectDigest]...)
}

func outputTransform(name, typeRef string, output []byte, createModule string) []byte {
	data := append([]byte(name), []byte(typeRef)...)
	data = append(data, output...)
	typeOffset := len(name)
	outputOffset := typeOffset + len(typeRef)

	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

	// Function types: create, write, close, transform.
	types := []byte{0x04}
	types = append(types, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f)
	types = append(types, 0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7f)
	types = append(types, 0x60, 0x01, 0x7f, 0x01, 0x7f)
	types = append(types, 0x60, 0x00, 0x01, 0x7f)
	module = appendSection(module, 1, types)

	imports := []byte{0x03}
	imports = appendName(imports, createModule)
	imports = appendName(imports, "output_create")
	imports = append(imports, 0x00, 0x00)
	imports = appendName(imports, "enbu")
	imports = appendName(imports, "output_write")
	imports = append(imports, 0x00, 0x01)
	imports = appendName(imports, "enbu")
	imports = appendName(imports, "output_close")
	imports = append(imports, 0x00, 0x02)
	module = appendSection(module, 2, imports)

	module = appendSection(module, 3, []byte{0x01, 0x03})
	module = appendSection(module, 5, []byte{0x01, 0x00, 0x01})

	exports := []byte{0x01}
	exports = appendName(exports, "enbu_transform")
	exports = append(exports, 0x00, 0x03)
	module = appendSection(module, 7, exports)

	body := []byte{0x01, 0x01, 0x7f} // one i32 local
	body = appendConst(body, 0)
	body = appendConst(body, int32(len(name)))
	body = appendConst(body, int32(typeOffset))
	body = appendConst(body, int32(len(typeRef)))
	body = append(body, 0x10, 0x00, 0x21, 0x00) // call create; local.set 0
	body = append(body, 0x20, 0x00)             // local.get 0
	body = appendConst(body, int32(outputOffset))
	body = appendConst(body, int32(len(output)))
	body = append(body, 0x10, 0x01, 0x1a) // call write; drop
	body = append(body, 0x20, 0x00, 0x10, 0x02, 0x1a)
	body = appendConst(body, 0)
	body = append(body, 0x0b)
	code := []byte{0x01}
	code = appendU32(code, uint32(len(body)))
	code = append(code, body...)
	module = appendSection(module, 10, code)

	dataSection := []byte{0x01, 0x00}
	dataSection = appendConst(dataSection, 0)
	dataSection = append(dataSection, 0x0b)
	dataSection = appendU32(dataSection, uint32(len(data)))
	dataSection = append(dataSection, data...)
	module = appendSection(module, 11, dataSection)
	return module
}

func inputLenProbe(handle int32) []byte {
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	types := []byte{0x02}
	types = append(types, 0x60, 0x01, 0x7f, 0x01, 0x7e)
	types = append(types, 0x60, 0x00, 0x01, 0x7f)
	module = appendSection(module, 1, types)
	imports := []byte{0x01}
	imports = appendName(imports, "enbu")
	imports = appendName(imports, "input_len")
	imports = append(imports, 0x00, 0x00)
	module = appendSection(module, 2, imports)
	module = appendSection(module, 3, []byte{0x01, 0x01})
	exports := []byte{0x01}
	exports = appendName(exports, "enbu_transform")
	exports = append(exports, 0x00, 0x01)
	module = appendSection(module, 7, exports)
	body := []byte{0x00}
	body = appendConst(body, handle)
	body = append(body, 0x10, 0x00, 0x1a)
	body = appendConst(body, 0)
	body = append(body, 0x0b)
	code := []byte{0x01}
	code = appendU32(code, uint32(len(body)))
	code = append(code, body...)
	return appendSection(module, 10, code)
}

func readAtProbe(handle int32, offset int64, length int32) []byte {
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	types := []byte{0x02}
	types = append(types, 0x60, 0x04, 0x7f, 0x7e, 0x7f, 0x7f, 0x01, 0x7f)
	types = append(types, 0x60, 0x00, 0x01, 0x7f)
	module = appendSection(module, 1, types)
	imports := []byte{0x01}
	imports = appendName(imports, "enbu")
	imports = appendName(imports, "read_at")
	imports = append(imports, 0x00, 0x00)
	module = appendSection(module, 2, imports)
	module = appendSection(module, 3, []byte{0x01, 0x01})
	module = appendSection(module, 5, []byte{0x01, 0x00, 0x01})
	exports := []byte{0x01}
	exports = appendName(exports, "enbu_transform")
	exports = append(exports, 0x00, 0x01)
	module = appendSection(module, 7, exports)
	body := []byte{0x00}
	body = appendConst(body, handle)
	body = appendI64Const(body, offset)
	body = appendConst(body, 0)
	body = appendConst(body, length)
	body = append(body, 0x10, 0x00, 0x1a)
	body = appendConst(body, 0)
	body = append(body, 0x0b)
	code := []byte{0x01}
	code = appendU32(code, uint32(len(body)))
	code = append(code, body...)
	return appendSection(module, 10, code)
}

// noImportInfiniteLoop has no host calls, so CallLimit cannot stop it. The
// body loops with br 0 forever and proves the host-owned wall-clock deadline
// reaches guest execution even when the caller supplies Background.
func noImportInfiniteLoop() []byte {
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module = appendSection(module, 1, []byte{0x01, 0x60, 0x00, 0x01, 0x7f})
	module = appendSection(module, 3, []byte{0x01, 0x00})
	exports := []byte{0x01}
	exports = appendName(exports, "enbu_transform")
	exports = append(exports, 0x00, 0x00)
	module = appendSection(module, 7, exports)
	body := []byte{
		0x00,       // no locals
		0x03, 0x40, // loop with empty block type
		0x0c, 0x00, // br 0
		0x0b,       // end loop (unreachable at runtime)
		0x41, 0x00, // i32.const 0 satisfies the function result type
		0x0b, // end function
	}
	code := []byte{0x01}
	code = appendU32(code, uint32(len(body)))
	code = append(code, body...)
	return appendSection(module, 10, code)
}

func appendSection(module []byte, id byte, payload []byte) []byte {
	module = append(module, id)
	module = appendU32(module, uint32(len(payload)))
	return append(module, payload...)
}

func appendName(destination []byte, value string) []byte {
	destination = appendU32(destination, uint32(len(value)))
	return append(destination, value...)
}

func appendU32(destination []byte, value uint32) []byte {
	for {
		current := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			current |= 0x80
		}
		destination = append(destination, current)
		if value == 0 {
			return destination
		}
	}
}

func appendConst(destination []byte, value int32) []byte {
	return appendSignedConst(destination, 0x41, int64(value))
}

func appendI64Const(destination []byte, value int64) []byte {
	return appendSignedConst(destination, 0x42, value)
}

func appendSignedConst(destination []byte, opcode byte, value int64) []byte {
	destination = append(destination, opcode)
	for {
		current := byte(value & 0x7f)
		value >>= 7
		done := (value == 0 && current&0x40 == 0) || (value == -1 && current&0x40 != 0)
		if !done {
			current |= 0x80
		}
		destination = append(destination, current)
		if done {
			return destination
		}
	}
}

func FuzzDecodeContracts(f *testing.F) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	pkg, err := NewPackage(minimalTransform, "issuer.example.com", "plugin:fuzz", []TypeNamespace{testNamespace})
	if err != nil {
		f.Fatal(err)
	}
	pkg, err = SignPackage(pkg, private)
	if err != nil {
		f.Fatal(err)
	}
	encodedPackage, err := EncodePackage(pkg)
	if err != nil {
		f.Fatal(err)
	}
	packageDigest, err := PackageDigest(pkg)
	if err != nil {
		f.Fatal(err)
	}
	grant, err := NewTrustGrant(
		TrustScopeLocal,
		packageDigest,
		pkg.Issuer,
		pkg.Subject,
		pkg.OutputNamespaces,
		public,
	)
	if err != nil {
		f.Fatal(err)
	}
	encodedGrant, err := EncodeTrustGrant(grant)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(uint8(0), encodedPackage)
	f.Add(uint8(1), encodedGrant)
	f.Add(uint8(0), []byte{0xff})
	f.Fuzz(func(t *testing.T, contract uint8, encoded []byte) {
		if contract%2 == 0 {
			_, _ = DecodePackage(encoded)
			return
		}
		_, _ = DecodeTrustGrant(encoded)
	})
}
