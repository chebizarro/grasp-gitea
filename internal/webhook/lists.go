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
		tags = append(tags, nostr.Tag{"a", repoRef, "wss://relay.sharegap.net", listType})
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

	ev := &nostr.Event{
		Kind:    KindNIP32Label,
		Content: labelName,
		Tags: nostr.Tags{
			{"L", labelNS},
			{"l", labelName, labelNS},
			{"a", repoTag},
			{"e", targetID},
			{"k", fmt.Sprintf("%d", targetKind)},
		},
	}

	return h.publish(ctx, ev)
}
