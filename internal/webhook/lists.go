package webhook

import (
	"context"
	"fmt"

	"fiatjaf.com/nostr"

	"github.com/sharegap/grasp-gitea/internal/store"
)

// PublishUserGraspList publishes a kind:10317 user grasp list event.
// This is a replaceable event (d-tag = "grasp") listing repos the user
// tracks, maintains, or watches.
func (h *Handler) PublishUserGraspList(ctx context.Context, userPubkey string, repos []store.Mapping, listType string) error {
	tags := nostr.Tags{
		{"d", listType}, // e.g. "watched", "maintained", "contributed"
	}
	for _, m := range repos {
		repoRef := fmt.Sprintf("%s/%s", m.Npub, m.RepoID)
		tags = append(tags, nostr.Tag{"a", repoRef, h.relayHint, listType})
	}

	ev := &nostr.Event{
		Kind:    nostr.Kind(10317),
		Content: "",
		Tags:    tags,
	}

	return h.publish(ctx, ev)
}

// PublishNIP32Label publishes a kind:1985 NIP-32 label event.
// Used when a Gitea label is applied to an issue or PR.
func (h *Handler) PublishNIP32Label(ctx context.Context, mapping store.Mapping, targetKind int, targetID string, labelName string, labelNS string) error {
	repoTag := fmt.Sprintf("%s/%s", mapping.Npub, mapping.RepoID)

	if labelNS == "" {
		labelNS = "gitea"
	}

	tags := nostr.Tags{
		{"L", labelNS},
		{"l", labelName, labelNS},
		{"a", repoTag},
	}
	// Only emit e/k tags when there is a valid target event ID.
	// Standalone label-created events (no issue/PR subject) must not emit {"e", ""}.
	if targetID != "" {
		tags = append(tags, nostr.Tag{"e", targetID})
		tags = append(tags, nostr.Tag{"k", fmt.Sprintf("%d", targetKind)})
	}

	ev := &nostr.Event{
		Kind:    KindNIP32Label,
		Content: labelName,
		Tags:    tags,
	}

	return h.publish(ctx, ev)
}
