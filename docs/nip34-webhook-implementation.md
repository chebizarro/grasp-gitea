# NIP-34 Webhook Implementation

## Overview

This implementation adds full NIP-34 event support for Gitea webhooks, enabling the bridge to publish events for pull requests, issues, patches, and labels to Nostr relays.

## What Was Added

### New Event Kinds Supported

| Kind  | Description                | Use Case                        |
|-------|----------------------------|---------------------------------|
| 1617  | Patch                      | Push to `refs/nostr/<event-id>` |
| 1618  | PR Open                    | Pull request opened             |
| 1619  | PR Update                  | PR updated/closed/synchronized  |
| 1621  | Issue                      | Issue opened/edited/closed      |
| 1630  | Status: Open               | PR/Issue opened                 |
| 1631  | Status: Applied            | PR merged                       |
| 1632  | Status: Closed             | PR/Issue closed                 |
| 1633  | Status: Draft              | PR marked as draft              |
| 1985  | NIP-32 Label               | Issue/PR labeled                |

### New Files

1. **`internal/webhook/types.go`** - Gitea webhook payload types
2. **`internal/webhook/handler.go`** - Main webhook handler with event processing
3. **`internal/webhook/README.md`** - Documentation and setup guide

### Modified Files

1. **`internal/relay/kinds.go`** - Added NIP-34 event kind constants
2. **`internal/publisher/service.go`** - Added `PublishEvent()` method for webhook events
3. **`internal/api/server.go`** - Added webhook handler wiring
4. **`internal/config/config.go`** - Added `GiteaWebhookSecret` configuration
5. **`internal/metrics/metrics.go`** - Added webhook event metrics
6. **`cmd/grasp-bridge/main.go`** - Initialized webhook handler
7. **`.env.example`** - Documented new environment variables

## Configuration

### Environment Variables

```bash
# Required: Bridge signing key for publishing events
BRIDGE_NSEC=nsec1... or hex private key

# Required: HMAC secret shared with Gitea webhook
GITEA_WEBHOOK_SECRET=your-secret-here

# Optional: Relay URLs to publish to
RELAY_URLS=wss://relay1.example.com,wss://relay2.example.com
```

### Gitea System Webhook Setup

1. Navigate to **Site Administration → System Webhooks**
2. Click **Add Webhook → Gitea**
3. Configure:
   - **Target URL**: `http://grasp-bridge:8090/webhook/gitea`
   - **HTTP Method**: `POST`
   - **POST Content Type**: `application/json`
   - **Secret**: Same value as `GITEA_WEBHOOK_SECRET`
   - **Trigger On**: Select all events (Push, Create, Delete, Pull Request, Issues, Label)
   - **Active**: ✓

## Event Flow

```
Gitea Event → /webhook/gitea → Handler → Publisher → Nostr Relays
                     ↓
               HMAC Verification
                     ↓
               Event Transformation
                     ↓
               Bridge Signing
                     ↓
               Metrics Tracking
```

## Security

- **HMAC Signature Verification**: All webhook requests are verified using HMAC-SHA256
- **Bridge Signing**: All events are signed with the bridge's private key (`BRIDGE_NSEC`)
- **Secret Management**: Webhook secret should be a strong random value (32+ characters)

## Metrics

The implementation tracks:
- `webhook_events_received` - Total webhook events received from Gitea
- `webhook_events_published` - Successfully published NIP-34 events to relays
- `webhook_events_failed` - Failed event publications

## Event Examples

### Pull Request Open (kind:1618)

```json
{
  "kind": 1618,
  "pubkey": "bridge_pubkey",
  "created_at": 1234567890,
  "tags": [
    ["a", "npub1.../repo-id"],
    ["p", "npub1..."],
    ["r", "npub1.../repo-id/pull/42"],
    ["title", "Fix authentication bug"],
    ["head", "feature/auth-fix"],
    ["base", "main"]
  ],
  "content": "This PR fixes the authentication timeout issue...",
  "sig": "..."
}
```

### Issue (kind:1621)

```json
{
  "kind": 1621,
  "pubkey": "bridge_pubkey",
  "created_at": 1234567890,
  "tags": [
    ["a", "npub1.../repo-id"],
    ["p", "npub1..."],
    ["r", "npub1.../repo-id/issue/123"],
    ["title", "Add dark mode support"],
    ["action", "opened"]
  ],
  "content": "We should add dark mode to improve UX...",
  "sig": "..."
}
```

### Status Event (kind:1630)

```json
{
  "kind": 1630,
  "pubkey": "bridge_pubkey",
  "created_at": 1234567890,
  "tags": [
    ["e", "event_id_of_pr_or_issue"],
    ["p", "npub1..."]
  ],
  "content": "",
  "sig": "..."
}
```

### NIP-32 Label (kind:1985)

```json
{
  "kind": 1985,
  "pubkey": "bridge_pubkey",
  "created_at": 1234567890,
  "tags": [
    ["L", "gitea/label"],
    ["l", "bug", "gitea/label"],
    ["a", "1621:npub1.../npub1.../repo-id/issue/123"],
    ["p", "npub1..."]
  ],
  "content": "",
  "sig": "..."
}
```

## Supported Webhook Events

### Push Events
- **Regular push** → Publishes `kind:30618` (repository state)
- **Patch push** (`refs/nostr/<event-id>`) → Handles `kind:1617` (patch acknowledgement)

### Branch/Tag Events
- **Create** → Publishes `kind:30618` (repository state)
- **Delete** → Publishes `kind:30618` (repository state)

### Pull Request Events
- **Opened** → `kind:1618` (PR open) + `kind:1630/1633` (status)
- **Closed** → `kind:1619` (PR update) + `kind:1631/1632` (status)
- **Reopened** → `kind:1619` (PR update) + `kind:1630` (status)
- **Edited** → `kind:1619` (PR update)
- **Synchronized** → `kind:1619` (PR update)

### Issue Events
- **Opened** → `kind:1621` (issue) + `kind:1630` (status)
- **Closed** → `kind:1621` (issue) + `kind:1632` (status)
- **Reopened** → `kind:1621` (issue) + `kind:1630` (status)
- **Edited** → `kind:1621` (issue)
- **Labeled** → `kind:1985` (NIP-32 label)
- **Unlabeled** → `kind:1985` (NIP-32 label)

## Testing

To test the webhook handler:

1. Set up environment variables
2. Start grasp-bridge
3. Configure Gitea system webhook
4. Create a test PR or issue in a provisioned repository
5. Check logs for webhook events
6. Verify events on Nostr relays using a relay explorer

## Future Enhancements

- [ ] Fetch pre-published `kind:1617` patch events from relays
- [ ] Emit `kind:1631` (applied) status for merged patches
- [ ] Support for `kind:10317` user repository tracking lists
- [ ] Webhook event replay/recovery mechanism
- [ ] Rate limiting for webhook endpoints
- [ ] Webhook event queue for reliability

## References

- [NIP-34: git stuff](https://github.com/nostr-protocol/nips/blob/master/34.md)
- [NIP-32: Labeling](https://github.com/nostr-protocol/nips/blob/master/32.md)
- [Gitea Webhooks Documentation](https://docs.gitea.com/usage/webhooks)
