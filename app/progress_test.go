package app

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

type recordingEvents struct {
	messages []string
	steps    []ProgressStep
}

func (r *recordingEvents) OnProgress(message string) {
	r.messages = append(r.messages, message)
}

func (r *recordingEvents) OnStepProgress(step ProgressStep) {
	r.steps = append(r.steps, step)
}

func (*recordingEvents) OnConflictRetry(int, int) {}

func TestEmitStepProgress(t *testing.T) {
	t.Run("nil handler", func(t *testing.T) {
		(&App{}).emitStepProgress("pull", "decrypt", "done")
	})

	t.Run("forwards exact step", func(t *testing.T) {
		events := &recordingEvents{}
		a := &App{Events: events}
		a.emitStepProgress("sync", "push", "done")
		want := []ProgressStep{{Op: "sync", Step: "push", Status: "done"}}
		if !reflect.DeepEqual(events.steps, want) {
			t.Fatalf("steps = %#v, want %#v", events.steps, want)
		}
	})
}

func TestProgressStepJSONContract(t *testing.T) {
	got, err := json.Marshal(ProgressStep{Op: "add", Step: "encrypt", Status: "start"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"op":"add","step":"encrypt","status":"start"}` {
		t.Fatalf("JSON = %s", got)
	}
}

func TestSuccessfulProgressPathsEmitDone(t *testing.T) {
	t.Run("direct pull", func(t *testing.T) {
		a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
		events := &recordingEvents{}
		a.Events = events
		if _, _, err := a.PullSecrets(context.Background(), "default"); err != nil {
			t.Fatal(err)
		}
		assertLastStep(t, events.steps, ProgressStep{Op: "pull", Step: "cache", Status: "done"})
	})

	t.Run("pull without secrets", func(t *testing.T) {
		a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
		events := &recordingEvents{}
		a.Events = events
		if _, _, err := a.PullSecrets(context.Background(), "default"); err != nil {
			t.Fatal(err)
		}
		assertLastStep(t, events.steps, ProgressStep{Op: "pull", Step: "download", Status: "done"})
	})

	t.Run("delete absent secret", func(t *testing.T) {
		a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
		events := &recordingEvents{}
		a.Events = events
		if err := a.DeleteSecret(context.Background(), "default", "MISSING"); err != nil {
			t.Fatal(err)
		}
		assertLastStep(t, events.steps, ProgressStep{Op: "delete", Step: "pull_secrets", Status: "done"})
	})

	t.Run("sync without secrets", func(t *testing.T) {
		a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
		events := &recordingEvents{}
		a.Events = events
		if err := a.SyncSecrets(context.Background(), "default"); err != nil {
			t.Fatal(err)
		}
		assertLastStep(t, events.steps, ProgressStep{Op: "sync", Step: "pull_secrets", Status: "done"})
	})
}

func assertLastStep(t *testing.T, steps []ProgressStep, want ProgressStep) {
	t.Helper()
	if len(steps) == 0 || steps[len(steps)-1] != want {
		t.Fatalf("steps = %#v, want final %#v", steps, want)
	}
}
