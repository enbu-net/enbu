package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/plugin"
	"github.com/opencontainers/go-digest"
)

var (
	transformNamespace = plugin.TypeNamespace{Group: "scanner.example.com", Version: "v1"}
	transformType      = artifact.TypeRef{Group: transformNamespace.Group, Version: transformNamespace.Version, Kind: "FindingSet"}
)

func TestPluginTransformerStreamsMultipleInputsAndPreservesRecipientIntersection(t *testing.T) {
	objects := newMemoryObjects()
	devices, verifier := newTransformDevices(t, 3)
	policy := digest.FromString("plugin transform policy")
	inputSchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")

	firstPayload := []byte("firmware:")
	first := sealTransformInput(t, objects, devices[0], []artifact.VerifiedDevice{devices[0].verified, devices[1].verified}, inputSchema,
		testUUID(t, "71717171-7171-4171-8171-717171717171"), firstPayload, policy)
	secondPayload := []byte("ssid=lab")
	second := sealTransformInput(t, objects, devices[0], []artifact.VerifiedDevice{devices[0].verified, devices[2].verified}, inputSchema,
		testUUID(t, "72727272-7272-4272-8272-727272727272"), secondPayload, policy)
	openedFirst := openTransformInput(t, objects, devices[0].identity, verifier, first.Ref)
	openedSecond := openTransformInput(t, objects, devices[0].identity, verifier, second.Ref)

	module := transformConcatModule("findings", transformType.String(), []int{len(firstPayload), len(secondPayload)})
	verifiedPackage := newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace})
	host, err := plugin.NewHost(plugin.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	relation, _ := artifact.ParseTypeRef("relations.enbu.net/v1alpha1/DerivedFrom")
	edge := artifact.Edge{
		ID: testUUID(t, "73737373-7373-4373-8373-737373737373"), Name: "source",
		Relation: relation, Strength: artifact.EdgeLogical, Target: first.Revision.UID,
	}
	temporaryParent := filepath.Join(t.TempDir(), "plugin-private")
	transformer := PluginTransformer{
		Host: host, Source: objects, TempDir: temporaryParent,
		Sealer: Sealer{
			Sink: objects, Issuer: devices[0].identity,
			Recipients: []artifact.VerifiedDevice{devices[0].verified, devices[1].verified, devices[2].verified},
		},
	}
	outputUID := testUUID(t, "74747474-7474-4474-8474-747474747474")
	result, err := transformer.Transform(context.Background(), PluginTransformRequest{
		Package: verifiedPackage,
		Inputs: []PluginInputSelection{
			{Opened: openedFirst, Payload: "data"},
			{Opened: openedSecond, Payload: "data"},
		},
		Outputs: []PluginOutputPlan{{
			Slot: "findings", UID: outputUID,
			Metadata: artifact.Metadata{
				Name:   "firmware Wi-Fi findings",
				Labels: map[string]string{"enbu.net/generated": "true"},
			},
			PayloadName: "findings.txt", PayloadMediaType: "text/plain", Edges: []artifact.Edge{edge},
		}},
		PolicyRevision: policy,
	})
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if result.Package != verifiedPackage.Digest() || len(result.Outputs) != 1 {
		t.Fatalf("result = %#v", result)
	}
	sealed := result.Outputs[0]
	if sealed.Revision.UID != outputUID || sealed.Revision.Schema != transformType ||
		sealed.Revision.Metadata.Labels["enbu.net/generated"] != "true" || len(sealed.Revision.Edges) != 1 {
		t.Fatalf("host-owned output revision = %#v", sealed.Revision)
	}

	openedOutput := openTransformInput(t, objects, devices[0].identity, verifier, sealed.Ref)
	if len(openedOutput.Grant.Claims.Recipients) != 1 || openedOutput.Grant.Claims.Recipients[0].DeviceID != devices[0].verified.DeviceID() {
		t.Fatalf("output recipients = %#v", openedOutput.Grant.Claims.Recipients)
	}
	var plaintext bytes.Buffer
	if err := openedOutput.WritePayload(context.Background(), objects, "findings.txt", &plaintext); err != nil {
		t.Fatal(err)
	}
	if want := append(append([]byte(nil), firstPayload...), secondPayload...); !bytes.Equal(plaintext.Bytes(), want) {
		t.Fatalf("output = %q, want %q", plaintext.Bytes(), want)
	}
	if _, err := OpenRevision(context.Background(), objects, devices[1].identity, verifier, sealed.Ref); !errors.Is(err, artifact.ErrGrantAccessDenied) {
		t.Fatalf("non-intersection recipient opened output: %v", err)
	}
	entries, err := os.ReadDir(temporaryParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("plaintext execution storage remains: %#v", entries)
	}
}

func TestPluginTransformerFailsClosedOnEmptyRecipientIntersection(t *testing.T) {
	objects := newMemoryObjects()
	devices, verifier := newTransformDevices(t, 2)
	policy := digest.FromString("empty intersection policy")
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	first := sealTransformInput(t, objects, devices[0], []artifact.VerifiedDevice{devices[0].verified}, schema,
		testUUID(t, "75757575-7575-4575-8575-757575757575"), []byte("a"), policy)
	second := sealTransformInput(t, objects, devices[1], []artifact.VerifiedDevice{devices[1].verified}, schema,
		testUUID(t, "76767676-7676-4676-8676-767676767676"), []byte("b"), policy)
	openedFirst := openTransformInput(t, objects, devices[0].identity, verifier, first.Ref)
	openedSecond := openTransformInput(t, objects, devices[1].identity, verifier, second.Ref)
	module := transformConcatModule("result", transformType.String(), []int{1, 1})
	host, _ := plugin.NewHost(plugin.DefaultLimits())
	transformer := PluginTransformer{
		Host: host, Source: objects, TempDir: filepath.Join(t.TempDir(), "private"),
		Sealer: Sealer{Sink: objects, Issuer: devices[0].identity, Recipients: []artifact.VerifiedDevice{devices[0].verified, devices[1].verified}},
	}
	_, err := transformer.Transform(context.Background(), PluginTransformRequest{
		Package:        newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace}),
		Inputs:         []PluginInputSelection{{Opened: openedFirst, Payload: "data"}, {Opened: openedSecond, Payload: "data"}},
		Outputs:        []PluginOutputPlan{{Slot: "result", UID: testUUID(t, "77777777-7777-4777-8777-777777777777"), Metadata: artifact.Metadata{Name: "result"}, PayloadName: "data", PayloadMediaType: "application/octet-stream"}},
		PolicyRevision: policy,
	})
	if !errors.Is(err, ErrEmptyRecipientIntersection) {
		t.Fatalf("error = %v", err)
	}
}

func TestPluginTransformerRejectsNamespaceAndOpenedRevisionTampering(t *testing.T) {
	objects := newMemoryObjects()
	devices, verifier := newTransformDevices(t, 1)
	policy := digest.FromString("namespace policy")
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	sealed := sealTransformInput(t, objects, devices[0], []artifact.VerifiedDevice{devices[0].verified}, schema,
		testUUID(t, "78787878-7878-4878-8878-787878787878"), []byte("firmware"), policy)
	opened := openTransformInput(t, objects, devices[0].identity, verifier, sealed.Ref)
	host, _ := plugin.NewHost(plugin.DefaultLimits())
	plan := PluginOutputPlan{Slot: "result", UID: testUUID(t, "79797979-7979-4979-8979-797979797979"), Metadata: artifact.Metadata{Name: "result"}, PayloadName: "data", PayloadMediaType: "application/octet-stream"}
	transformer := PluginTransformer{
		Host: host, Source: objects, TempDir: filepath.Join(t.TempDir(), "private"),
		Sealer: Sealer{Sink: objects, Issuer: devices[0].identity, Recipients: []artifact.VerifiedDevice{devices[0].verified}},
	}

	t.Run("reserved output namespace", func(t *testing.T) {
		module := transformConcatModule("result", "schemas.enbu.net/v1alpha1/SecretMap", []int{8})
		_, err := transformer.Transform(context.Background(), PluginTransformRequest{
			Package: newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace}),
			Inputs:  []PluginInputSelection{{Opened: opened, Payload: "data"}}, Outputs: []PluginOutputPlan{plan}, PolicyRevision: policy,
		})
		if !errors.Is(err, plugin.ErrExecution) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("opened type-state mutation", func(t *testing.T) {
		mutated := opened
		mutated.Revision.Metadata.Name = "modified after verification"
		module := transformConcatModule("result", transformType.String(), []int{8})
		_, err := transformer.Transform(context.Background(), PluginTransformRequest{
			Package: newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace}),
			Inputs:  []PluginInputSelection{{Opened: mutated, Payload: "data"}}, Outputs: []PluginOutputPlan{plan}, PolicyRevision: policy,
		})
		if !errors.Is(err, ErrObjectMismatch) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("duplicate selected handle", func(t *testing.T) {
		module := transformConcatModule("result", transformType.String(), []int{8, 8})
		_, err := transformer.Transform(context.Background(), PluginTransformRequest{
			Package: newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace}),
			Inputs:  []PluginInputSelection{{Opened: opened, Payload: "data"}, {Opened: opened, Payload: "data"}},
			Outputs: []PluginOutputPlan{plan}, PolicyRevision: policy,
		})
		if !errors.Is(err, ErrInvalidPluginTransform) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestPluginTransformerCancellationCleansPlaintextStorage(t *testing.T) {
	objects := newMemoryObjects()
	devices, verifier := newTransformDevices(t, 1)
	policy := digest.FromString("cancel policy")
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	payload := bytes.Repeat([]byte("firmware"), 10_000)
	sealed := sealTransformInput(t, objects, devices[0], []artifact.VerifiedDevice{devices[0].verified}, schema,
		testUUID(t, "81818181-8181-4181-8181-818181818181"), payload, policy)
	opened := openTransformInput(t, objects, devices[0].identity, verifier, sealed.Ref)
	module := transformConcatModule("result", transformType.String(), []int{len(payload)})
	host, _ := plugin.NewHost(plugin.DefaultLimits())
	ctx, cancel := context.WithCancel(context.Background())
	temporaryParent := filepath.Join(t.TempDir(), "private")
	transformer := PluginTransformer{
		Host: host, Source: cancelingObjectSource{ObjectSource: objects, cancel: cancel}, TempDir: temporaryParent,
		Sealer: Sealer{Sink: objects, Issuer: devices[0].identity, Recipients: []artifact.VerifiedDevice{devices[0].verified}},
	}
	_, err := transformer.Transform(ctx, PluginTransformRequest{
		Package:        newVerifiedTransformPackage(t, module, []plugin.TypeNamespace{transformNamespace}),
		Inputs:         []PluginInputSelection{{Opened: opened, Payload: "data"}},
		Outputs:        []PluginOutputPlan{{Slot: "result", UID: testUUID(t, "82828282-8282-4282-8282-828282828282"), Metadata: artifact.Metadata{Name: "result"}, PayloadName: "data", PayloadMediaType: "application/octet-stream"}},
		PolicyRevision: policy,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	entries, readErr := os.ReadDir(temporaryParent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary storage after cancel = %#v", entries)
	}
}

func TestOpenPluginDraftRejectsDescriptorAndContentTampering(t *testing.T) {
	objects := newMemoryObjects()
	descriptor, err := objects.Ingest(context.Background(), plugin.MediaTypeDraft, strings.NewReader("plaintext draft"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("descriptor", func(t *testing.T) {
		object := objects.values[descriptor.Digest]
		object.descriptor.Size++
		objects.values[descriptor.Digest] = object
		if _, err := openPluginDraft(context.Background(), objects, descriptor); !errors.Is(err, ErrObjectMismatch) {
			t.Fatalf("error = %v", err)
		}
		object.descriptor.Size--
		objects.values[descriptor.Digest] = object
	})

	t.Run("content", func(t *testing.T) {
		object := objects.values[descriptor.Digest]
		object.data[0] ^= 0xff
		objects.values[descriptor.Digest] = object
		reader, err := openPluginDraft(context.Background(), objects, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.ReadAll(reader)
		_ = reader.Close()
		if !errors.Is(readErr, ErrObjectMismatch) {
			t.Fatalf("read error = %v", readErr)
		}
	})
}

type transformDevice struct {
	identity *artifact.DeviceIdentity
	verified artifact.VerifiedDevice
}

func newTransformDevices(t *testing.T, count int) ([]transformDevice, *enrollment.Verifier) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := enrollment.NewAuthority("plugins.identity.enbu.test", public)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := enrollment.NewVerifier([]enrollment.Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	result := make([]transformDevice, 0, count)
	for index := range count {
		identity, err := artifact.GenerateDeviceIdentity()
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := enrollment.Sign(enrollment.Claims{
			Issuer: "plugins.identity.enbu.test", DeviceID: identity.DeviceID(), Subject: "github:plugin-user:" + strconv.Itoa(index),
			X25519Recipient: identity.RecipientString(), Ed25519PublicKey: identity.SigningPublicKey(),
		}, private)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := artifact.VerifyEnrollment(context.Background(), verifier, assertion)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, transformDevice{identity: identity, verified: verified})
	}
	return result, verifier
}

func sealTransformInput(
	t *testing.T,
	objects *memoryObjects,
	issuer transformDevice,
	recipients []artifact.VerifiedDevice,
	schema artifact.TypeRef,
	uid artifact.UUID,
	payload []byte,
	policy digest.Digest,
) SealedRevision {
	t.Helper()
	sealed, err := (Sealer{Sink: objects, Issuer: issuer.identity, Recipients: recipients}).SealDraft(context.Background(), Draft{
		Kind: artifact.KindResource, UID: uid, Schema: schema, Metadata: artifact.Metadata{Name: "input"},
		Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: bytes.NewReader(payload)}},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func openTransformInput(
	t *testing.T,
	objects *memoryObjects,
	device *artifact.DeviceIdentity,
	verifier *enrollment.Verifier,
	ref artifact.SealedRef,
) OpenedRevision {
	t.Helper()
	opened, err := OpenRevision(context.Background(), objects, device, verifier, ref)
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

func newVerifiedTransformPackage(t *testing.T, module []byte, namespaces []plugin.TypeNamespace) plugin.VerifiedPackage {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := plugin.NewPackage(module, "plugins.example.com", "plugin:transform-test", namespaces)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = plugin.SignPackage(pkg, private)
	if err != nil {
		t.Fatal(err)
	}
	packageDigest, err := plugin.PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := plugin.NewTrustGrant(plugin.TrustScopeLocal, packageDigest, pkg.Issuer, pkg.Subject, pkg.OutputNamespaces, public)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := plugin.VerifyPackage(pkg, grant)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type cancelingObjectSource struct {
	artifact.ObjectSource
	cancel context.CancelFunc
}

func (source cancelingObjectSource) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	reader, descriptor, err := source.ObjectSource.Open(ctx, value)
	if err == nil {
		source.cancel()
	}
	return reader, descriptor, err
}

func transformConcatModule(slot, typeRef string, inputSizes []int) []byte {
	dataOffset := 4096
	data := append([]byte(slot), []byte(typeRef)...)
	typeOffset := dataOffset + len(slot)

	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	types := []byte{0x07}
	types = append(types, 0x60, 0x00, 0x01, 0x7f)                         // input_count
	types = append(types, 0x60, 0x01, 0x7f, 0x01, 0x7e)                   // input_len
	types = append(types, 0x60, 0x04, 0x7f, 0x7e, 0x7f, 0x7f, 0x01, 0x7f) // read_at
	types = append(types, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f) // output_create
	types = append(types, 0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x01, 0x7f)       // output_write
	types = append(types, 0x60, 0x01, 0x7f, 0x01, 0x7f)                   // output_close
	types = append(types, 0x60, 0x00, 0x01, 0x7f)                         // transform
	module = wasmSection(module, 1, types)

	imports := []byte{0x06}
	for index, name := range []string{"input_count", "input_len", "read_at", "output_create", "output_write", "output_close"} {
		imports = wasmName(imports, "enbu")
		imports = wasmName(imports, name)
		imports = append(imports, 0x00, byte(index))
	}
	module = wasmSection(module, 2, imports)
	module = wasmSection(module, 3, []byte{0x01, 0x06})
	module = wasmSection(module, 5, []byte{0x01, 0x00, 0x01})
	exports := []byte{0x01}
	exports = wasmName(exports, "enbu_transform")
	exports = append(exports, 0x00, 0x06)
	module = wasmSection(module, 7, exports)

	body := []byte{0x01, 0x01, 0x7f}
	body = append(body, 0x10, 0x00, 0x1a) // input_count; drop
	memoryOffset := 0
	for handle, size := range inputSizes {
		body = wasmI32(body, int32(handle))
		body = append(body, 0x10, 0x01, 0x1a) // input_len; drop
		body = wasmI32(body, int32(handle))
		body = wasmI64(body, 0)
		body = wasmI32(body, int32(memoryOffset))
		body = wasmI32(body, int32(size))
		body = append(body, 0x10, 0x02, 0x1a) // read_at; drop
		memoryOffset += size
	}
	body = wasmI32(body, int32(dataOffset))
	body = wasmI32(body, int32(len(slot)))
	body = wasmI32(body, int32(typeOffset))
	body = wasmI32(body, int32(len(typeRef)))
	body = append(body, 0x10, 0x03, 0x21, 0x00)
	body = append(body, 0x20, 0x00)
	body = wasmI32(body, 0)
	body = wasmI32(body, int32(memoryOffset))
	body = append(body, 0x10, 0x04, 0x1a)
	body = append(body, 0x20, 0x00, 0x10, 0x05, 0x1a)
	body = wasmI32(body, 0)
	body = append(body, 0x0b)
	code := []byte{0x01}
	code = wasmU32(code, uint32(len(body)))
	code = append(code, body...)
	module = wasmSection(module, 10, code)

	dataSection := []byte{0x01, 0x00}
	dataSection = wasmI32(dataSection, int32(dataOffset))
	dataSection = append(dataSection, 0x0b)
	dataSection = wasmU32(dataSection, uint32(len(data)))
	dataSection = append(dataSection, data...)
	return wasmSection(module, 11, dataSection)
}

func wasmSection(module []byte, id byte, payload []byte) []byte {
	module = append(module, id)
	module = wasmU32(module, uint32(len(payload)))
	return append(module, payload...)
}

func wasmName(destination []byte, value string) []byte {
	destination = wasmU32(destination, uint32(len(value)))
	return append(destination, value...)
}

func wasmU32(destination []byte, value uint32) []byte {
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

func wasmI32(destination []byte, value int32) []byte {
	return wasmSigned(destination, 0x41, int64(value))
}

func wasmI64(destination []byte, value int64) []byte {
	return wasmSigned(destination, 0x42, value)
}

func wasmSigned(destination []byte, opcode byte, value int64) []byte {
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
