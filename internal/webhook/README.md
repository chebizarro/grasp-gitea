# Webhook Handler

This package implements NIP-34 event publishing for Gitea webhook events.

## Supported Events

### Repository Events
- **Push** (`refs/heads/*`, `refs/tags/*`) → `kind:30618` (repository state)
- **Push** (`refs/nostr/<event-id>`) → `kind:1617` (patch acknowledgement)
- **Create** (branch/tag) → `kind:30618` (repository state)
- **Delete** (branch/tag) → `kind:30618` (repository state)

### Pull Request Events
- **PR Opened** → `kind:1618` (PR open)
- **PR Updated/Closed/Synchronized** → `kind:1619` (PR update)
- **PR Status** → `kind:1630/1631/1632/1633` (open/applied/closed/draft)

### Issue Events
- **Issue Opened/Edited/Closed** → `kind:1621` (issue)
- **Issue Status** → `kind:1630/1632` (open/closed)
- **Issue Labeled** → `kind:1985` (NIP-32 label)

### Label Events
- **Label Created/Edited/Deleted** → Informational only (logged)

## Configuration

Set these environment variables:

```bash
# Required: Bridge signing key for publishing events
BRIDGE_NSEC=nsec1... or hex private key

# Required: HMAC secret shared with Gitea webhook
GITEA_WEBHOOK_SECRET=your-secret-here

# Optional: Relay URLs to publish to (defaults to embedded relay)
RELAY_URLS=wss://relay1.example.com,wss://relay2.example.com
```

## Gitea Webhook Setup

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
Gitea Event → Webhook Handler → Publisher Service → Nostr Relays
                    ↓
              Metrics Tracking
```

## Metrics

The handler tracks:
- `webhook_events_received` - Total webhook events received
- `webhook_events_published` - Successfully published NIP-34 events
- `webhook_events_failed` - Failed event publications

## NIP-34 Event Kinds

| Kind  | Description                | Triggered By                    |
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
| 30618 | Repository State           | Push/create/delete              |

## Security

- HMAC signature verification prevents unauthorized webhook calls
- All events are signed with the bridge's private key (`BRIDGE_NSEC`)
- Webhook secret should be a strong random value (32+ characters)

## Example Event Tags

### PR Open (kind:1618)
```json
{
  "kind": 1618,
  "tags": [
    ["a", "npub1.../repo-id"],
    ["p", "npub1..."],
    ["r", "npub1.../repo-id/pull/42"],
    ["title", "Fix authentication bug"],
    ["head", "feature/auth-fix"],
    ["base", "main"]
  ],
  "content": "This PR fixes the authentication timeout issue..."
}
```

### Issue (kind:1621)
```json
{
  "kind": 1621,
  "tags": [
    ["a", "npub1.../repo-id"],
    ["p", "npub1..."],
    ["r", "npub1.../repo-id/issue/123"],
    ["title", "Add dark mode support"],
    ["action", "opened"]
  ],
  "content": "We should add dark mode to improve UX..."
}
```

### NIP-32 Label (kind:1985)
```json
{
  "kind": 1985,
  "tags": [
    ["L", "gitea/label"],
    ["l", "bug", "gitea/label"],
    ["a", "1621:npub1.../npub1.../repo-id/issue/123"],
    ["p", "npub1..."]
  ]
}
```
