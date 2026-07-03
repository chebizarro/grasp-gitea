# kind:10317 User GRASP List Design Finding

## Decision

Path B: the bridge must not mint or sign `kind:10317` user GRASP list events with `BRIDGE_NSEC`.

## Why

NIP-34 defines `kind:10317` as the **User grasp list**: a replaceable event containing `g` tags for the GRASP service websocket URLs a user generally wants to use for NIP-34 activity. Because `10317` is in Nostr's replaceable-event range, the effective list is scoped by `(pubkey, kind)`.

That means the signer is the subject of the list. If this bridge signs a `kind:10317` with the bridge key while trying to describe a repository owner's preferences, relays and clients will correctly interpret it as the bridge account's GRASP list, not the owner's list. This would repeat the same attribution problem avoided for `kind:30617` repository announcements: owner-owned content must be owner-signed, while the bridge may only sign facts it asserts itself, such as mirrored repository state (`kind:30618`) and CI workflow runs (`kind:5401`).

## Correct owner-driven design

A semantically correct implementation would be owner-driven:

1. The repository owner signs and publishes their own `kind:10317` event.
2. The bridge may subscribe for, fetch, validate, and cache the latest owner-signed `kind:10317` for known owner pubkeys.
3. If useful for relay propagation, the bridge may rebroadcast that exact event bytes/event object verbatim, preserving the owner's `pubkey`, `id`, and `sig`.
4. The bridge must never rewrite the tags, update the timestamp, or sign a replacement with `BRIDGE_NSEC`.

This is analogous to the existing `kind:30617` announcement cache/republish flow: the bridge stores an owner-signed event and rebroadcasts it unchanged, rather than manufacturing owner content.

## Current bridge behavior

Current bridge flows do not ingest or cache owner-signed `kind:10317` events. Without such an observed owner-signed event, there is nothing valid for the bridge to publish. The publisher therefore exposes only a guardrail that rejects bridge-signed user GRASP list publication attempts.

## Legitimate future bridge work

Future work can add owner-signed `10317` support without violating the signer invariant by:

- subscribing to `kind:10317` for provisioned owner pubkeys;
- validating the event signature and expected owner pubkey;
- caching the latest replaceable event per owner;
- optionally rebroadcasting the cached event verbatim; and
- optionally using the `g` URLs as discovery hints for owner-preferred GRASP servers.
