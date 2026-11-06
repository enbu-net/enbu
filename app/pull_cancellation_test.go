package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

type cancelPullEvents struct {
	recordingEvents
	cancel context.CancelFunc
}

func TestDotenvHistoryCancellationDoesNotRenderOutput(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			a := newAlice(t)
			path := writeOutput(t, a, "LOCAL_ONLY=personal\n")
			data, kept, removed, err := dotenvWithLocal(path, map[string]string{"KEY": "value"}, false, func() (map[string]bool, error) {
				return nil, fmt.Errorf("history read: %w", cause)
			})
			if !errors.Is(err, cause) || data != nil || kept != nil || removed != nil {
				t.Fatalf("canceled history rendered output: data=%q kept=%v removed=%v err=%v", data, kept, removed, err)
			}
		})
	}
}

func (e *cancelPullEvents) OnStepProgress(step ProgressStep) {
	e.recordingEvents.OnStepProgress(step)
	if step == (ProgressStep{Op: "pull", Step: "write", Status: "start"}) {
		e.cancel()
	}
}

func TestCanceledPullPreservesOriginalOutput(t *testing.T) {
	for _, phase := range []string{"history-list", "history-blob", "write-replace"} {
		t.Run(phase, func(t *testing.T) {
			a := newAlice(t)
			original := "KEY=old\nLOCAL_ONLY=personal\n"
			path := writeOutput(t, a, original)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			states, blobs := 0, 0
			a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
				Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
					if kind == storage.KindState {
						states++
						if phase == "history-list" && states == 2 {
							cancel()
						}
					}
					return next.Discover(ctx, kind, scope)
				},
				OpenBlob: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
					blobs++
					if phase == "history-blob" && blobs == 2 {
						cancel()
					}
					return next.OpenBlob(ctx, kind, scope, rev, index)
				},
			})
			if phase == "write-replace" {
				a.Events = &cancelPullEvents{cancel: cancel}
			}
			written, err := a.PullSecretsToFileWith(ctx, "default", phase == "write-replace")
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("cancellation point not reached: states=%d blobs=%d", states, blobs)
			}
			if !errors.Is(err, context.Canceled) || written != nil {
				t.Errorf("canceled pull acknowledged a write: result=%+v err=%v", written, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != original {
				t.Errorf("canceled pull changed the original file: %q err=%v", got, err)
			}
			a.Events = nil
			if _, err := a.PullSecretsToFileWith(t.Context(), "default", false); err != nil {
				t.Fatalf("fresh pull did not recover: %v", err)
			}
		})
	}
}
