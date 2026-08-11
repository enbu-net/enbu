package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/internal/apphost"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/tui"
	"github.com/spf13/cobra"
)

type runtimeFactory func(context.Context) (*apphost.Runtime, apphost.ProductionIdentity, error)

const defaultDeviceClientID = "Ov23li6nFmfdF4FW9ikd"

type authDependencies struct {
	browserLogin func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error)
	deviceLogin  func(context.Context, string, auth.DevicePrompter) (*auth.StoredToken, error)
	openBrowser  auth.BrowserOpener
	loadToken    func() (*auth.StoredToken, error)
	deleteToken  func() error
}

func New(version string) *cobra.Command { return newCommand(version, apphost.NewProduction) }

func newCommand(version string, factory runtimeFactory) *cobra.Command {
	var jsonOutput bool
	root := &cobra.Command{
		Use: "enbu", Short: "Encrypted artifact workspace manager",
		SilenceErrors: true, SilenceUsage: true,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "write one JSON result")
	root.AddCommand(
		newVersionCommand(version, &jsonOutput),
		newAuthCommand(&jsonOutput, authDependencies{
			browserLogin: auth.Login,
			deviceLogin:  auth.LoginDevice,
			openBrowser:  auth.OpenBrowser,
			loadToken:    auth.LoadToken,
			deleteToken:  auth.DeleteToken,
		}),
		newInitCommand(factory, &jsonOutput),
		newListCommand(factory, &jsonOutput),
		newHistoryCommand(factory, &jsonOutput),
		newTUICommand(factory),
		newImportCommand(factory, &jsonOutput),
		newImportTreeCommand(factory, &jsonOutput),
		newMaterializeCommand(factory, &jsonOutput),
		newEnrollmentCommand(factory, &jsonOutput),
		newPluginCommand(factory, &jsonOutput),
	)
	return root
}

func newPluginCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	command := &cobra.Command{Use: "plugin", Short: "Manage verified WASM transforms"}
	command.AddCommand(&cobra.Command{Use: "install PACKAGE TRUST", Args: cobra.ExactArgs(2), RunE: func(command *cobra.Command, args []string) error {
		packagePath, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		trustPath, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		packageSource, err := host.NewFileInput(packagePath)
		if err != nil {
			return err
		}
		trustSource, err := host.NewFileInput(trustPath)
		if err != nil {
			return err
		}
		packageReader, err := packageSource.Open(command.Context())
		if err != nil {
			return err
		}
		defer func() { _ = packageReader.Close() }()
		trustReader, err := trustSource.Open(command.Context())
		if err != nil {
			return err
		}
		defer func() { _ = trustReader.Close() }()
		return withRuntime(command.Context(), factory, func(runtime *apphost.Runtime, _ apphost.ProductionIdentity) error {
			digestValue, err := runtime.InstallPlugin(command.Context(), packageReader, trustReader)
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, map[string]string{"digest": digestValue.String()})
		})
	}})
	return command
}

func newImportTreeCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	var name, directory string
	command := &cobra.Command{Use: "import-tree LOGICAL_PATH=FILE...", Args: cobra.MinimumNArgs(1), RunE: func(command *cobra.Command, args []string) error {
		rootPath, err := filepath.Abs(directory)
		if err != nil {
			return err
		}
		type filePlan struct{ logical, native string }
		plans := make([]filePlan, 0, len(args))
		for _, argument := range args {
			logical, native, found := strings.Cut(argument, "=")
			if !found || logical == "" || native == "" {
				return errors.New("cli: each tree input must be LOGICAL_PATH=FILE")
			}
			absolute, err := filepath.Abs(native)
			if err != nil {
				return err
			}
			plans = append(plans, filePlan{logical: logical, native: absolute})
		}
		sort.Slice(plans, func(left, right int) bool { return plans[left].logical < plans[right].logical })
		return withWorkspace(command, []string{rootPath}, factory, func(session *apphost.Session) error {
			snapshot, err := session.Workspace().Snapshot(command.Context())
			if err != nil || len(snapshot.Frontier) != 1 {
				return errors.Join(err, errors.New("cli: workspace frontier is not singular"))
			}
			page, err := session.Workspace().ListResources(command.Context(), host.ListResourcesRequest{AtCommit: snapshot.Frontier[0], PageSize: host.MaxQueryPageSize})
			if err != nil {
				return err
			}
			var root host.ResourceMetadata
			for _, resource := range page.Resources {
				if resource.Kind == artifact.KindCollection {
					root = resource
					break
				}
			}
			parameters := make([]host.TransformParameter, 0, len(plans))
			payloads := make([]host.TransformPayload, 0, len(plans)+1)
			for index, plan := range plans {
				source, err := host.NewFileInput(plan.native)
				if err != nil {
					return err
				}
				handle, err := session.Workspace().RegisterInput(command.Context(), source)
				if err != nil {
					return err
				}
				parameters = append(parameters, host.TransformParameter{Name: plan.logical, Source: handle})
				payloads = append(payloads, host.TransformPayload{Name: fmt.Sprintf("file-%04d", index+1), MediaType: "application/octet-stream"})
			}
			payloads = append(payloads, host.TransformPayload{Name: "filetree-index", MediaType: "application/vnd.enbu.schema.file-tree-index.v1+cbor"})
			uid, edgeID, err := randomPair()
			if err != nil {
				return err
			}
			transform, _ := artifact.ParseTypeRef("transforms.enbu.net/v1alpha1/FileTreeImport")
			operation, err := session.Workspace().Start(command.Context(), host.TransformAction{
				BaseCommit: snapshot.Frontier[0], Transform: host.TransformRef{Builtin: transform}, Parameters: parameters,
				Outputs: []host.TransformOutput{{Slot: "tree", UID: uid, Metadata: artifact.Metadata{Name: name}, Parent: root.UID,
					ExpectedParent: root.Sealed, EdgeID: edgeID, EdgeName: name, Relation: artifact.MemberRelation(), Payloads: payloads}},
			})
			if err != nil {
				return err
			}
			outcome, err := session.Workspace().Wait(command.Context(), operation)
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, outcome)
		})
	}}
	command.Flags().StringVar(&name, "name", "file-tree", "resource and edge name")
	command.Flags().StringVar(&directory, "directory", ".", "workspace directory")
	return command
}

func newAuthCommand(jsonOutput *bool, dependencies authDependencies) *cobra.Command {
	authCommand := &cobra.Command{Use: "auth", Short: "Manage GitHub authentication"}
	var deviceFlow bool
	login := &cobra.Command{Use: "login", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		var token *auth.StoredToken
		var err error
		if deviceFlow {
			clientID := os.Getenv("ENBU_CLIENT_ID")
			if clientID == "" {
				clientID = defaultDeviceClientID
			}
			token, err = dependencies.deviceLogin(command.Context(), clientID, func(device auth.DeviceAuthorization) error {
				if _, writeErr := fmt.Fprintf(command.OutOrStdout(), "Code: %s\nVerification URL: %s\n", device.UserCode, device.VerificationURI); writeErr != nil {
					return writeErr
				}
				_ = dependencies.openBrowser(device.VerificationURI)
				return nil
			})
		} else {
			token, err = dependencies.browserLogin(command.Context(), dependencies.openBrowser)
		}
		if err != nil {
			return err
		}
		return printResult(command, jsonOutput, map[string]any{"authenticated": true, "username": token.Username})
	}}
	login.Flags().BoolVar(&deviceFlow, "device", false, "use GitHub Device Flow")
	status := &cobra.Command{Use: "status", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		token, err := dependencies.loadToken()
		if err != nil {
			var applicationError *apperr.Error
			if errors.As(apperr.Normalize(err), &applicationError) && applicationError.Code() == apperr.CodeNotAuthenticated {
				return printResult(command, jsonOutput, map[string]any{"authenticated": false})
			}
			return err
		}
		return printResult(command, jsonOutput, map[string]any{"authenticated": true, "username": token.Username})
	}}
	logout := &cobra.Command{Use: "logout", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if err := dependencies.deleteToken(); err != nil {
			return err
		}
		return printResult(command, jsonOutput, map[string]any{"logged_out": true})
	}}
	authCommand.AddCommand(login, status, logout)
	return authCommand
}

func newTUICommand(factory runtimeFactory) *cobra.Command {
	return &cobra.Command{Use: "tui [directory]", Args: cobra.MaximumNArgs(1), RunE: func(command *cobra.Command, args []string) error {
		return withWorkspace(command, args, factory, func(session *apphost.Session) error {
			return tui.Run(command.Context(), session.Workspace())
		})
	}}
}

func newVersionCommand(version string, jsonOutput *bool) *cobra.Command {
	return &cobra.Command{Use: "version", Args: cobra.NoArgs, RunE: func(command *cobra.Command, _ []string) error {
		if *jsonOutput {
			return writeResult(command.OutOrStdout(), map[string]string{"version": version})
		}
		_, err := fmt.Fprintln(command.OutOrStdout(), version)
		return err
	}}
}

func newInitCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	var registry string
	command := &cobra.Command{Use: "init [directory]", Args: cobra.MaximumNArgs(1), RunE: func(command *cobra.Command, args []string) error {
		root, err := absoluteArgument(args)
		if err != nil {
			return err
		}
		return withRuntime(command.Context(), factory, func(runtime *apphost.Runtime, identity apphost.ProductionIdentity) error {
			session, operation, err := runtime.Initialize(command.Context(), apphost.InitializeRequest{Root: root, Registry: registry, Subject: identity.Subject})
			if err != nil {
				return err
			}
			defer session.Close(context.WithoutCancel(command.Context())) //nolint:errcheck
			outcome, err := session.Workspace().Wait(command.Context(), operation)
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, outcome)
		})
	}}
	command.Flags().StringVar(&registry, "registry", "", "exact OCI repository host/path")
	_ = command.MarkFlagRequired("registry")
	return command
}

func newListCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	return &cobra.Command{Use: "list [directory]", Args: cobra.MaximumNArgs(1), RunE: func(command *cobra.Command, args []string) error {
		return withWorkspace(command, args, factory, func(session *apphost.Session) error {
			snapshot, err := session.Workspace().Snapshot(command.Context())
			if err != nil || len(snapshot.Frontier) != 1 {
				return errors.Join(err, errors.New("cli: workspace frontier is not singular"))
			}
			var resources []host.ResourceMetadata
			var cursor host.QueryCursor
			for {
				page, err := session.Workspace().ListResources(command.Context(), host.ListResourcesRequest{AtCommit: snapshot.Frontier[0], PageSize: host.MaxQueryPageSize, Cursor: cursor})
				if err != nil {
					return err
				}
				resources = append(resources, page.Resources...)
				if page.Next == "" {
					break
				}
				cursor = page.Next
			}
			return printResult(command, jsonOutput, resources)
		})
	}}
}

func newHistoryCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	return &cobra.Command{Use: "history [directory]", Args: cobra.MaximumNArgs(1), RunE: func(command *cobra.Command, args []string) error {
		return withWorkspace(command, args, factory, func(session *apphost.Session) error {
			snapshot, err := session.Workspace().Snapshot(command.Context())
			if err != nil {
				return err
			}
			page, err := session.Workspace().ListCommits(command.Context(), host.ListCommitsRequest{Frontier: snapshot.Frontier, PageSize: host.MaxQueryPageSize})
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, page.Commits)
		})
	}}
}

func newImportCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	var name, format, mediaType string
	command := &cobra.Command{Use: "import-file FILE [directory]", Args: cobra.RangeArgs(1, 2), RunE: func(command *cobra.Command, args []string) error {
		transformKind := ""
		payloadName := "content"
		payloadMediaType := mediaType
		switch format {
		case "opaque":
			transformKind = "OpaqueImport"
		case "dotenv":
			transformKind, payloadName, payloadMediaType = "DotEnvImport", "secrets.env", "text/plain"
		case "csv":
			transformKind, payloadName, payloadMediaType = "CSVImport", "table.csv", "text/csv"
		case "json":
			transformKind, payloadName, payloadMediaType = "JSONImport", "value.json", "application/json"
		default:
			return errors.New("cli: format must be one of opaque, dotenv, csv, or json")
		}
		file, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		workspaceArgs := args[1:]
		return withWorkspace(command, workspaceArgs, factory, func(session *apphost.Session) error {
			snapshot, err := session.Workspace().Snapshot(command.Context())
			if err != nil || len(snapshot.Frontier) != 1 {
				return errors.Join(err, errors.New("cli: workspace frontier is not singular"))
			}
			page, err := session.Workspace().ListResources(command.Context(), host.ListResourcesRequest{AtCommit: snapshot.Frontier[0], PageSize: host.MaxQueryPageSize})
			if err != nil {
				return err
			}
			var root host.ResourceMetadata
			for _, resource := range page.Resources {
				if resource.Kind == artifact.KindCollection {
					root = resource
					break
				}
			}
			inputSource, err := host.NewFileInput(file)
			if err != nil {
				return err
			}
			input, err := session.Workspace().RegisterInput(command.Context(), inputSource)
			if err != nil {
				return err
			}
			uid, edgeID, err := randomPair()
			if err != nil {
				return err
			}
			transform, _ := artifact.ParseTypeRef("transforms.enbu.net/v1alpha1/" + transformKind)
			operation, err := session.Workspace().Start(command.Context(), host.TransformAction{
				BaseCommit: snapshot.Frontier[0], Transform: host.TransformRef{Builtin: transform},
				Parameters: []host.TransformParameter{{Name: "input", Source: input}},
				Outputs:    []host.TransformOutput{{Slot: "input", UID: uid, Metadata: artifact.Metadata{Name: name}, Parent: root.UID, ExpectedParent: root.Sealed, EdgeID: edgeID, EdgeName: name, Relation: artifact.MemberRelation(), Payloads: []host.TransformPayload{{Name: payloadName, MediaType: payloadMediaType}}}},
			})
			if err != nil {
				return err
			}
			outcome, err := session.Workspace().Wait(command.Context(), operation)
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, outcome)
		})
	}}
	command.Flags().StringVar(&name, "name", "imported-file", "resource and edge name")
	command.Flags().StringVar(&format, "format", "opaque", "input format: opaque, dotenv, csv, or json")
	command.Flags().StringVar(&mediaType, "media-type", "application/octet-stream", "opaque input media type")
	return command
}

func newMaterializeCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	var payload, format string
	command := &cobra.Command{Use: "materialize RESOURCE_UID OUTPUT [directory]", Args: cobra.RangeArgs(2, 3), RunE: func(command *cobra.Command, args []string) error {
		uid, err := artifact.ParseUUID(args[0])
		if err != nil {
			return err
		}
		outputPath, err := filepath.Abs(args[1])
		if err != nil {
			return err
		}
		return withWorkspace(command, args[2:], factory, func(session *apphost.Session) error {
			snapshot, err := session.Workspace().Snapshot(command.Context())
			if err != nil || len(snapshot.Frontier) != 1 {
				return errors.Join(err, errors.New("cli: workspace frontier is not singular"))
			}
			target, err := host.NewSecureFileOutput(outputPath)
			if err != nil {
				return err
			}
			handle, err := session.Workspace().RegisterOutput(command.Context(), target)
			if err != nil {
				return err
			}
			formatRef, err := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/" + format)
			if err != nil {
				return err
			}
			operation, err := session.Workspace().Start(command.Context(), host.MaterializeAction{AtCommit: snapshot.Frontier[0], Target: uid, Format: formatRef, Payload: payload, Destination: handle})
			if err != nil {
				return err
			}
			outcome, err := session.Workspace().Wait(command.Context(), operation)
			if err != nil {
				return err
			}
			return printResult(command, jsonOutput, outcome)
		})
	}}
	command.Flags().StringVar(&payload, "payload", "", "exact named stream for multi-stream resources")
	command.Flags().StringVar(&format, "format", "Raw", "trusted materializer kind")
	return command
}

func newEnrollmentCommand(factory runtimeFactory, jsonOutput *bool) *cobra.Command {
	command := &cobra.Command{Use: "enrollment"}
	command.AddCommand(&cobra.Command{Use: "request SUBJECT OUTPUT", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(cmd.Context(), factory, func(runtime *apphost.Runtime, _ apphost.ProductionIdentity) error {
			encoded, err := runtime.CreateEnrollmentRequest(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return os.WriteFile(args[1], encoded, 0o600)
		})
	}})
	command.AddCommand(&cobra.Command{Use: "approve REQUEST SUBJECT OUTPUT [directory]", Args: cobra.RangeArgs(3, 4), RunE: func(cmd *cobra.Command, args []string) error {
		root, err := absoluteArgument(args[3:])
		if err != nil {
			return err
		}
		request, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		return withRuntime(cmd.Context(), factory, func(runtime *apphost.Runtime, _ apphost.ProductionIdentity) error {
			assertion, err := runtime.ApproveEnrollment(cmd.Context(), root, request, args[1])
			if err != nil {
				return err
			}
			return os.WriteFile(args[2], assertion, 0o600)
		})
	}})
	command.AddCommand(&cobra.Command{Use: "import ASSERTION [directory]", Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
		root, err := absoluteArgument(args[1:])
		if err != nil {
			return err
		}
		assertion, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		return withRuntime(cmd.Context(), factory, func(runtime *apphost.Runtime, _ apphost.ProductionIdentity) error {
			return runtime.ImportEnrollment(cmd.Context(), root, assertion)
		})
	}})
	_ = jsonOutput
	return command
}

func withWorkspace(command *cobra.Command, args []string, factory runtimeFactory, run func(*apphost.Session) error) error {
	root, err := absoluteArgument(args)
	if err != nil {
		return err
	}
	return withRuntime(command.Context(), factory, func(runtime *apphost.Runtime, _ apphost.ProductionIdentity) error {
		session, err := runtime.Open(command.Context(), root)
		if err != nil {
			return err
		}
		defer session.Close(context.WithoutCancel(command.Context())) //nolint:errcheck
		return run(session)
	})
}

func withRuntime(ctx context.Context, factory runtimeFactory, run func(*apphost.Runtime, apphost.ProductionIdentity) error) error {
	runtime, identity, err := factory(ctx)
	if err != nil {
		return err
	}
	defer runtime.Close(context.WithoutCancel(ctx)) //nolint:errcheck
	return run(runtime, identity)
}

func absoluteArgument(args []string) (string, error) {
	if len(args) > 1 {
		return "", errors.New("cli: too many directory arguments")
	}
	value := "."
	if len(args) == 1 {
		value = args[0]
	}
	return filepath.Abs(value)
}

func randomPair() (artifact.UUID, artifact.UUID, error) {
	first, err := randomUUID()
	if err != nil {
		return "", "", err
	}
	second, err := randomUUID()
	return first, second, err
}

func randomUUID() (artifact.UUID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return artifact.ParseUUID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]))
}

func printResult(command *cobra.Command, jsonOutput *bool, value any) error {
	if *jsonOutput {
		return writeResult(command.OutOrStdout(), value)
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), string(encoded))
	return err
}

func writeResult(output io.Writer, value any) error { return json.NewEncoder(output).Encode(value) }

func NormalizeExecutionError(err error) error { return apphost.NormalizeError(err) }

func RenderExecutionError(command *cobra.Command, err error, _ []string) {
	payload := apperr.PayloadOf(NormalizeExecutionError(err))
	if command.Flags().Lookup("json") != nil {
		jsonValue, flagErr := command.Flags().GetBool("json")
		if flagErr == nil && jsonValue {
			_ = writeResult(command.ErrOrStderr(), map[string]any{"error": payload})
			return
		}
	}
	_, _ = fmt.Fprintln(command.ErrOrStderr(), payload.Message)
}
