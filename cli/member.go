package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func recipientKind(recipient string) string {
	if strings.HasPrefix(recipient, "age1tag1") {
		return "P-256 (hardware)"
	}
	return "X25519"
}

func newMemberCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{Use: "member", Short: "Manage who is trusted in this workspace", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error { return renderHelp(cmd) }}
	cmd.AddCommand(newMemberListCommand(a), newMemberRequestsCommand(a), newMemberApproveCommand(a), newMemberRemoveCommand(a), newMemberAdminCommand(a), newMemberResolveForkCommand(a))
	return cmd
}

func newMemberListCommand(a *app.App) *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List the members of this workspace", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			members, err := a.ListMembers(cmd.Context())
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"members": members})
			}
			for _, m := range members {
				role := "member"
				if m.Admin {
					role = "admin"
				}
				you := ""
				if m.Self {
					you = "  (you)"
				}
				cmd.Printf("%s  %-6s  %s%s\n", m.Fingerprint, role, recipientKind(m.Recipient), you)
			}
			return nil
		}}
}

func newMemberRequestsCommand(a *app.App) *cobra.Command {
	return &cobra.Command{Use: "requests", Short: "List devices waiting for approval", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			requests, err := a.ListJoinRequests(cmd.Context())
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"requests": requests})
			}
			if len(requests) == 0 {
				cmd.Println("No pending requests")
				return nil
			}
			for _, r := range requests {
				cmd.Printf("%s  %s  requested %s\n", r.Fingerprint, recipientKind(r.Recipient), r.RequestedAt.Format(time.DateTime))
			}
			return nil
		}}
}

// memberTarget is something a member command can act on.
type memberTarget struct {
	deviceID, fingerprint, detail string
}

// choose resolves which device to act on. With --device it is explicit.
// Otherwise one candidate is taken directly and several are offered as a list,
// so nobody has to copy a device id by hand.
func choose(cmd *cobra.Command, device, title string, candidates []memberTarget) (memberTarget, error) {
	if device != "" {
		for _, c := range candidates {
			if c.deviceID == device || strings.EqualFold(c.fingerprint, device) {
				return c, nil
			}
		}
		return memberTarget{}, invalidArgument("no such device", nil)
	}
	if len(candidates) == 0 {
		return memberTarget{}, invalidArgument("there is nobody to choose", nil)
	}
	if !interactive(cmd) {
		return memberTarget{}, invalidArgument("not a terminal: pass --device <device-id or fingerprint>", nil)
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	items := make([]pickerItem, len(candidates))
	for i, c := range candidates {
		items[i] = pickerItem{Label: c.fingerprint, Detail: c.detail}
	}
	idx, err := pick(cmd, title, items)
	if errors.Is(err, errPickerCancelled) {
		return memberTarget{}, cancelled(cmd)
	}
	if err != nil {
		return memberTarget{}, err
	}
	return candidates[idx], nil
}

// confirmTarget shows what is about to happen. It is skipped by --yes and when
// the device was named explicitly, since naming it is the decision.
func confirmTarget(cmd *cobra.Command, explicit, yes bool, action string, t memberTarget) error {
	if yes || explicit || !interactive(cmd) {
		return nil
	}
	cmd.PrintErrf("%s\n  fingerprint: %s\n  %s\n", action, t.fingerprint, t.detail)
	ok, err := confirm(cmd, "Does the fingerprint match what the person sees on their device?")
	if err != nil {
		return err
	}
	if !ok {
		return cancelled(cmd)
	}
	return nil
}

func newMemberApproveCommand(a *app.App) *cobra.Command {
	var device string
	var yes bool
	cmd := &cobra.Command{Use: "approve", Short: "Approve a device that asked to join", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			requests, err := a.ListJoinRequests(cmd.Context())
			if err != nil {
				return err
			}
			candidates := make([]memberTarget, len(requests))
			for i, r := range requests {
				candidates[i] = memberTarget{deviceID: r.DeviceID, fingerprint: r.Fingerprint,
					detail: fmt.Sprintf("%s, requested %s", recipientKind(r.Recipient), r.RequestedAt.Format(time.DateTime))}
			}
			if len(candidates) == 0 && device == "" {
				if jsonEnabled(cmd) {
					return invalidArgument("no pending requests", nil)
				}
				cmd.Println("No pending requests")
				return nil
			}
			target, err := choose(cmd, device, "Approve which device?", candidates)
			if err != nil {
				return err
			}
			if err := confirmTarget(cmd, device != "", yes, "Approving gives this device access to every secret.", target); err != nil {
				return err
			}
			if err := a.ApproveMember(cmd.Context(), target.deviceID); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"action": "approve", "device_id": target.deviceID, "fingerprint": target.fingerprint})
			}
			cmd.Printf("Approved %s and re-encrypted secrets for it\n", target.fingerprint)
			return nil
		}}
	cmd.Flags().StringVar(&device, "device", "", "Device id or fingerprint (skips the list)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip the fingerprint confirmation")
	return cmd
}

func memberCandidates(members []app.MemberInfo, includeSelf bool) []memberTarget {
	var out []memberTarget
	for _, m := range members {
		if m.Self && !includeSelf {
			continue
		}
		role := "member"
		if m.Admin {
			role = "admin"
		}
		out = append(out, memberTarget{deviceID: m.DeviceID, fingerprint: m.Fingerprint, detail: role + ", " + recipientKind(m.Recipient)})
	}
	return out
}

func newMemberRemoveCommand(a *app.App) *cobra.Command {
	var device string
	var yes bool
	cmd := &cobra.Command{Use: "remove", Short: "Remove a member and re-encrypt secrets without them", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			members, err := a.ListMembers(cmd.Context())
			if err != nil {
				return err
			}
			target, err := choose(cmd, device, "Remove which member?", memberCandidates(members, false))
			if err != nil {
				return err
			}
			if err := confirmTarget(cmd, device != "", yes, "Removing re-encrypts every environment without this device. Secrets it already read cannot be revoked; rotate them.", target); err != nil {
				return err
			}
			if err := a.RemoveMember(cmd.Context(), target.deviceID); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"action": "remove", "device_id": target.deviceID, "fingerprint": target.fingerprint})
			}
			cmd.Printf("Removed %s\n", target.fingerprint)
			return nil
		}}
	cmd.Flags().StringVar(&device, "device", "", "Device id or fingerprint (skips the list)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip the confirmation")
	return cmd
}

func newMemberAdminCommand(a *app.App) *cobra.Command {
	var device string
	var revoke, yes bool
	cmd := &cobra.Command{Use: "admin", Short: "Grant or revoke the right to manage members", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			members, err := a.ListMembers(cmd.Context())
			if err != nil {
				return err
			}
			target, err := choose(cmd, device, "Change which member?", memberCandidates(members, false))
			if err != nil {
				return err
			}
			if !revoke {
				// An admin can approve and remove devices, so granting it is as
				// sensitive as approving a device.
				if err := confirmTarget(cmd, device != "", yes, "An admin can approve and remove devices.", target); err != nil {
					return err
				}
			}
			if err := a.SetAdmin(cmd.Context(), target.deviceID, !revoke); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"action": "admin", "device_id": target.deviceID, "admin": !revoke})
			}
			if revoke {
				cmd.Printf("%s is no longer an admin\n", target.fingerprint)
			} else {
				cmd.Printf("%s is now an admin\n", target.fingerprint)
			}
			return nil
		}}
	cmd.Flags().StringVar(&device, "device", "", "Device id or fingerprint (skips the list)")
	cmd.Flags().BoolVar(&revoke, "revoke", false, "Revoke instead of grant")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip the confirmation")
	return cmd
}

func newMemberResolveForkCommand(a *app.App) *cobra.Command {
	return &cobra.Command{Use: "resolve-fork", Short: "Join member changes that two admins made at the same time", Args: appArgs(cobra.NoArgs),
		Long: `When two admins change the members at the same time, nothing proceeds until an
admin settles it. The result keeps only the members and admin rights that both
changes agree on; anyone left out can be approved again afterwards.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.ResolveControlFork(cmd.Context()); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"action": "resolve-fork"})
			}
			cmd.Println("✓ Member changes joined")
			return nil
		}}
}
