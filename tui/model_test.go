package tui

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/enbu-net/enbu/app"
)

func appJoinRequest(id, fingerprint string) app.JoinRequestInfo {
	return app.JoinRequestInfo{DeviceID: id, Fingerprint: fingerprint, Algorithm: "ed25519"}
}

func testModel() *model {
	m := newModel(nil)
	m.loading = false
	m.width = 90
	m.height = 24
	m.current = "development"
	m.repository = "owner/repo"
	m.envs = []envItem{{name: "development", isCurrent: true}, {name: "production"}}
	m.secrets = []secretEntry{{key: "API_KEY", value: "super-secret"}, {key: "DATABASE_URL", value: "postgres://db"}}
	m.resizeInputs()
	return m
}

func keyMsg(value string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: []rune(value)[0], Text: value}
}

func findHit(t *testing.T, m *model, kind hitKind, index int) hitRegion {
	t.Helper()
	for _, hit := range m.hits {
		if hit.kind == kind && hit.index == index {
			return hit
		}
	}
	t.Fatalf("hit region kind=%d index=%d not found", kind, index)
	return hitRegion{}
}

func TestViewDeclaresTerminalModes(t *testing.T) {
	view := testModel().View()
	if !view.AltScreen {
		t.Fatal("alternate screen is disabled")
	}
	if view.MouseMode != tea.MouseModeAllMotion {
		t.Fatalf("mouse mode = %v, want %v", view.MouseMode, tea.MouseModeAllMotion)
	}
}

func click(hit hitRegion) tea.MouseClickMsg {
	return tea.MouseClickMsg{
		X:      hit.x,
		Y:      hit.y,
		Button: tea.MouseLeft,
	}
}

func TestSecretsAreMaskedAndCanBeRevealed(t *testing.T) {
	m := testModel()
	view := m.View().Content
	if strings.Contains(view, "super-secret") {
		t.Fatal("secret is visible before reveal")
	}

	_, _ = m.Update(keyMsg(" "))
	if view = m.View().Content; !strings.Contains(view, "super-secret") {
		t.Fatal("secret is not visible after reveal")
	}

	reveal := findHit(t, m, hitReveal, 0)
	_, _ = m.Update(click(reveal))
	if view = m.View().Content; strings.Contains(view, "super-secret") {
		t.Fatal("secret remains visible after mouse toggle")
	}
}

func TestMouseSwitchesTabsAndRefreshesMembers(t *testing.T) {
	m := testModel()
	_ = m.View()
	members := findHit(t, m, hitTab, int(tabMembers))
	_, cmd := m.Update(click(members))
	if m.tab != tabMembers || !m.loading || cmd == nil {
		t.Fatalf("members tab state = tab %d loading %v cmd %v", m.tab, m.loading, cmd != nil)
	}

	msg := cmd()
	_, _ = m.Update(msg)
	if m.loading || len(m.recipients) == 0 {
		t.Fatalf("members did not load: loading=%v recipients=%d", m.loading, len(m.recipients))
	}
}

func TestMouseWheelScrollsLongSecretList(t *testing.T) {
	m := testModel()
	m.height = 16
	m.secrets = make([]secretEntry, 20)
	for i := range m.secrets {
		m.secrets[i] = secretEntry{key: "KEY", value: "VALUE"}
	}
	_ = m.View()
	_, _ = m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if m.offset != 3 {
		t.Fatalf("offset = %d, want 3", m.offset)
	}
}

func TestAddOverlaySupportsMouseFocusAndKeepsErrors(t *testing.T) {
	m := testModel()
	_ = m.View()
	add := findHit(t, m, hitAdd, 0)
	_, _ = m.Update(click(add))
	if m.overlay != overlayAdd || !m.keyInput.Focused() {
		t.Fatal("add overlay did not open with key focused")
	}

	_ = m.View()
	value := findHit(t, m, hitInputValue, 0)
	_, _ = m.Update(click(value))
	if !m.valueInput.Focused() || m.keyInput.Focused() {
		t.Fatal("mouse did not focus the value input")
	}

	_, _ = m.Update(errMsg{err: errors.New("network failed")})
	if m.overlay != overlayAdd || m.err == nil {
		t.Fatal("operation error closed the overlay or was lost")
	}
}

func TestAddOverlayEnterAdvancesToValueAndRejectsEmptyValue(t *testing.T) {
	m := testModel()
	m.openAdd()
	m.keyInput.SetValue("API_TOKEN")
	if view := m.View().Content; !strings.Contains(view, "enter value") {
		t.Fatalf("key step help is missing: %q", view)
	}

	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || m.loading || m.focusKey || !m.valueInput.Focused() || m.overlay != overlayAdd {
		t.Fatalf(
			"key enter state: cmd=%v loading=%v focusKey=%v valueFocused=%v overlay=%d",
			cmd != nil,
			m.loading,
			m.focusKey,
			m.valueInput.Focused(),
			m.overlay,
		)
	}

	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || m.loading || m.err == nil || m.err.Error() != "value cannot be empty" {
		t.Fatalf("empty value state: cmd=%v loading=%v err=%v", cmd != nil, m.loading, m.err)
	}

	m.valueInput.SetValue("secret")
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || !m.loading {
		t.Fatalf("value submit state: cmd=%v loading=%v", cmd != nil, m.loading)
	}
}

func TestCopyUsesInjectedClipboard(t *testing.T) {
	m := testModel()
	var copied string
	m.copyToClipboard = func(value string) error {
		copied = value
		return nil
	}
	_, cmd := m.copySecret(0, false)
	if cmd == nil {
		t.Fatal("copy command is nil")
	}
	_, _ = m.Update(cmd())
	if copied != "super-secret" || m.status != "Copied value" {
		t.Fatalf("copied=%q status=%q", copied, m.status)
	}
}

func TestSettingsEditorRejectsInvalidOutput(t *testing.T) {
	m := testModel()
	m.tab = tabSettings
	m.configContent = "version = \"v1alpha2\"\n"
	_, _ = m.startConfigEdit()
	m.configInput.SetValue("version = \"v1alpha2\"\n[env.default]\noutput = \"../outside\"\n")
	_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	if cmd != nil || m.err == nil || !m.configEditing {
		t.Fatalf("invalid config state: cmd=%v err=%v editing=%v", cmd != nil, m.err, m.configEditing)
	}
}

func TestEnvironmentChangeRemasksSecrets(t *testing.T) {
	m := testModel()
	m.revealed["API_KEY"] = true
	_, _ = m.Update(operationDoneMsg{message: "Switched"})
	if m.revealed["API_KEY"] {
		t.Fatal("revealed state survived workspace-changing operation")
	}
}

func TestWorkspaceLoadRemasksReplacedSecrets(t *testing.T) {
	m := testModel()
	m.revealed["API_KEY"] = true
	_, _ = m.Update(workspaceLoadedMsg{
		secrets: map[string]string{"API_KEY": "replacement"},
		envs:    m.envs,
		current: "development",
	})
	if m.revealed["API_KEY"] || strings.Contains(m.View().Content, "replacement") {
		t.Fatal("replacement workspace data remained revealed")
	}
}

func TestConfigSaveReloadsWorkspace(t *testing.T) {
	originalCurrent := demoCurrent
	originalEnvs := append([]envItem(nil), demoEnvs...)
	t.Cleanup(func() {
		demoCurrent = originalCurrent
		demoEnvs = originalEnvs
	})
	demoCurrent = "production"
	demoEnvs = []envItem{{name: "development"}, {name: "production", isCurrent: true}}

	m := testModel()
	m.tab = tabSettings
	m.configDraft = demoConfigContent
	_, cmd := m.Update(configSavedMsg{})
	if cmd == nil || !m.loading {
		t.Fatal("config save did not start a workspace reload")
	}
	_, _ = m.Update(cmd())
	if m.current != "production" || len(m.secrets) == 0 || m.status != "Saved enbu.toml" {
		t.Fatalf("workspace not refreshed: current=%q secrets=%d status=%q", m.current, len(m.secrets), m.status)
	}
}

func TestConfigCancelClearsValidationError(t *testing.T) {
	t.Run("keyboard", func(t *testing.T) {
		m := testModel()
		m.tab = tabSettings
		m.configContent = "version = \"v1alpha2\"\n"
		_, _ = m.startConfigEdit()
		m.err = errors.New("invalid config")
		_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
		if m.configEditing || m.err != nil {
			t.Fatalf("keyboard cancel: editing=%v err=%v", m.configEditing, m.err)
		}
	})

	t.Run("mouse", func(t *testing.T) {
		m := testModel()
		m.tab = tabSettings
		m.configContent = "version = \"v1alpha2\"\n"
		_, _ = m.startConfigEdit()
		m.err = errors.New("invalid config")
		_ = m.View()
		cancel := findHit(t, m, hitCancel, 0)
		_, _ = m.Update(click(cancel))
		if m.configEditing || m.err != nil {
			t.Fatalf("mouse cancel: editing=%v err=%v", m.configEditing, m.err)
		}
	})
}

func TestMouseTabNavigationCancelsConfigEditing(t *testing.T) {
	m := testModel()
	m.tab = tabSettings
	m.configContent = "version = \"v1alpha2\"\n"
	_, _ = m.startConfigEdit()
	m.configInput.SetValue("unsaved")
	_ = m.View()
	secrets := findHit(t, m, hitTab, int(tabSecrets))
	_, _ = m.Update(click(secrets))
	if m.tab != tabSecrets || m.configEditing || m.configInput.Focused() {
		t.Fatalf("tab navigation state: tab=%d editing=%v focused=%v", m.tab, m.configEditing, m.configInput.Focused())
	}
	before := m.configInput.Value()
	_, _ = m.Update(keyMsg("x"))
	if m.configInput.Value() != before {
		t.Fatal("input was routed to the hidden config editor")
	}
}

func TestTruncateHandlesLongAndWideValues(t *testing.T) {
	value := strings.Repeat("界", 4096)
	got := truncate(value, 12)
	if lipgloss.Width(got) > 12 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncate result has display width %d: %q", lipgloss.Width(got), got)
	}
}

func membersModel() *model {
	m := testModel()
	m.tab = tabMembers
	m.recipients = append(m.recipients, demoRecipients...)
	m.requests = append(m.requests, demoRequests...)
	m.requests = append(m.requests, appJoinRequest("second-device", "aaaa-bbbb-cccc-dddd-eeee"))
	return m
}

func TestMembersShowDevicesWaitingForApproval(t *testing.T) {
	m := membersModel()
	view := m.View().Content
	for _, want := range []string{"Waiting for approval", demoRequests[0].Fingerprint, "aaaa-bbbb-cccc-dddd-eeee", "Approve"} {
		if !strings.Contains(view, want) {
			t.Fatalf("members view lacks %q:\n%s", want, view)
		}
	}
	m.requests = nil
	if view := m.View().Content; strings.Contains(view, "Waiting for approval") {
		t.Fatalf("approval section shown with nothing waiting:\n%s", view)
	}
}

func TestApproveNeedsConfirmationAndShowsFingerprint(t *testing.T) {
	m := membersModel()
	_ = m.View()
	_, _ = m.Update(keyMsg("j")) // select the second request
	_, _ = m.Update(keyMsg("a"))
	if m.overlay != overlayApprove {
		t.Fatalf("overlay = %v, want approve", m.overlay)
	}
	view := m.View().Content
	if !strings.Contains(view, "aaaa-bbbb-cccc-dddd-eeee") || !strings.Contains(view, "Compare it with") {
		t.Fatalf("dialog does not show the fingerprint to compare:\n%s", view)
	}

	// Escape cancels without approving anything.
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.overlay != overlayNone || cmd != nil || len(m.requests) != 2 {
		t.Fatalf("cancel: overlay=%v cmd=%v requests=%d", m.overlay, cmd != nil, len(m.requests))
	}

	_, _ = m.Update(keyMsg("a"))
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || !m.loading {
		t.Fatalf("confirm did not start the approval: cmd=%v loading=%v", cmd != nil, m.loading)
	}
	done, ok := cmd().(memberApprovedMsg)
	if !ok || !strings.Contains(done.message, "aaaa-bbbb-cccc-dddd-eeee") {
		t.Fatalf("approval message = %#v", done)
	}
	_, reload := m.Update(done)
	if m.overlay != overlayNone || reload == nil || !strings.Contains(m.status, "Approved") {
		t.Fatalf("after approval: overlay=%v reload=%v status=%q", m.overlay, reload != nil, m.status)
	}
}

func TestApproveByMouseOpensTheSameConfirmation(t *testing.T) {
	m := membersModel()
	_ = m.View()
	hit := findHit(t, m, hitApprove, 1)
	_, _ = m.Update(click(hit))
	if m.overlay != overlayApprove || m.requestCursor != 1 {
		t.Fatalf("overlay=%v cursor=%d", m.overlay, m.requestCursor)
	}
}

func TestApproveDoesNothingWhenNobodyIsWaiting(t *testing.T) {
	m := membersModel()
	m.requests = nil
	_, _ = m.Update(keyMsg("a"))
	if m.overlay != overlayNone {
		t.Fatalf("overlay = %v with no requests", m.overlay)
	}
}

func TestRequestCursorStaysInRangeAfterReload(t *testing.T) {
	m := membersModel()
	m.requestCursor = 1
	_, _ = m.Update(recipientsLoadedMsg{recipients: m.recipients, requests: m.requests[:1]})
	if m.requestCursor != 0 {
		t.Fatalf("cursor = %d after the list shrank", m.requestCursor)
	}
	_, _ = m.Update(recipientsLoadedMsg{recipients: m.recipients})
	if m.requestCursor != 0 {
		t.Fatalf("cursor = %d with no requests", m.requestCursor)
	}
}

// The list can be reloaded while the dialog is open; the dialog is about the
// device whose fingerprint the admin was shown.
func TestApprovalDialogKeepsItsTargetWhenTheListChanges(t *testing.T) {
	m := membersModel()
	_ = m.View()
	_, _ = m.Update(keyMsg("j")) // the second request
	_, _ = m.Update(keyMsg("a"))
	shown := m.requests[1]

	for name, reloaded := range map[string][]app.JoinRequestInfo{
		"emptied":   nil,
		"reordered": {m.requests[1], m.requests[0]},
		"replaced":  {appJoinRequest("someone-else", "9999-9999-9999-9999-9999")},
	} {
		t.Run(name, func(t *testing.T) {
			m := membersModel()
			_ = m.View()
			_, _ = m.Update(keyMsg("j"))
			_, _ = m.Update(keyMsg("a"))
			_, _ = m.Update(recipientsLoadedMsg{recipients: m.recipients, requests: reloaded})
			view := m.View().Content // must not panic on an emptied list
			if !strings.Contains(view, shown.Fingerprint) {
				t.Fatalf("the dialog stopped showing %s:\n%s", shown.Fingerprint, view)
			}
			_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			if cmd == nil {
				t.Fatal("confirmation did nothing")
			}
			done, ok := cmd().(memberApprovedMsg)
			if !ok || !strings.Contains(done.message, shown.Fingerprint) {
				t.Fatalf("approved %#v, want the device that was shown (%s)", done, shown.Fingerprint)
			}
		})
	}
}

func TestMembersStayWhenOnlyTheRequestsFailToLoad(t *testing.T) {
	m := membersModel()
	_, _ = m.Update(recipientsLoadedMsg{recipients: m.recipients, requestsErr: errors.New("requests unavailable")})
	if len(m.recipients) == 0 {
		t.Fatal("the member list was discarded")
	}
	if m.err == nil || !strings.Contains(m.View().Content, "requests unavailable") {
		t.Fatalf("the failure was not shown: %v", m.err)
	}
	if m.loading {
		t.Fatal("still loading after the load finished")
	}
}

func TestFailedApprovalIsShownAndStopsLoading(t *testing.T) {
	m := membersModel()
	_ = m.View()
	_, _ = m.Update(keyMsg("a"))
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.loading {
		t.Fatal("approval did not start")
	}
	_, _ = m.Update(errMsg{errors.New("not allowed")})
	if m.loading || m.err == nil || !strings.Contains(m.View().Content, "not allowed") {
		t.Fatalf("loading=%v err=%v", m.loading, m.err)
	}
}

func TestClosingTheDialogForgetsItsTarget(t *testing.T) {
	m := membersModel()
	_ = m.View()
	_, _ = m.Update(keyMsg("a"))
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.approving != nil || m.overlay != overlayNone {
		t.Fatalf("approving=%v overlay=%v", m.approving, m.overlay)
	}
}
