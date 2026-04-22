# Beads - AI-Native Issue Tracking

Welcome to Beads! This repository uses **Beads** for issue tracking - a modern, AI-native tool designed to live directly in your codebase alongside your code.

## What is Beads?

Beads is issue tracking that lives in your repo, making it perfect for AI coding agents and developers who want their issues close to their code. No web UI required - everything works through the CLI and integrates seamlessly with git.

**Learn more:** [github.com/steveyegge/beads](https://github.com/steveyegge/beads)

## Quick Start

### Essential Commands

```bash
# Create new issues
bd create "Add user authentication"

# View all issues
bd list

# View issue details
bd show <issue-id>

# Update issue status
bd update <issue-id> --status in_progress
bd update <issue-id> --status done

# Sync with git remote
bd sync
```

### Working with Issues

Issues in Beads are:
- **Git-native**: Stored in `.beads/issues.jsonl` and synced like code
- **AI-friendly**: CLI-first design works perfectly with AI coding agents
- **Branch-aware**: Issues can follow your branch workflow
- **Always in sync**: Auto-syncs with your commits

## Why Beads?

✨ **AI-Native Design**
- Built specifically for AI-assisted development workflows
- CLI-first interface works seamlessly with AI coding agents
- No context switching to web UIs

🚀 **Developer Focused**
- Issues live in your repo, right next to your code
- Works offline, syncs when you push
- Fast, lightweight, and stays out of your way

🔧 **Git Integration**
- Automatic sync with git commits
- Branch-aware issue tracking
- Intelligent JSONL merge resolution

## Get Started with Beads

Try Beads in your own projects:

```bash
# Install Beads
curl -sSL https://raw.githubusercontent.com/steveyegge/beads/main/scripts/install.sh | bash

# Initialize in your repo
bd init

# Create your first issue
bd create "Try out Beads"
```

## Learn More

- **Documentation**: [github.com/steveyegge/beads/docs](https://github.com/steveyegge/beads/tree/main/docs)
- **Quick Start Guide**: Run `bd quickstart`
- **Examples**: [github.com/steveyegge/beads/examples](https://github.com/steveyegge/beads/tree/main/examples)

---

## Project Conventions

### Canonical tracker

`grasp-gitea/.beads/issues.jsonl` is the single source of truth for this project, even when work touches files in `fleet-planning` or other repos.

### Epic convention

Since `.beads/issues.jsonl` has no native epic or dependency fields:

- **Epics** use IDs like `epic-<domain>-NNN` (e.g. `epic-docs-001`)
- **Child issues** prefix their title with `[epic-<id>]` (e.g. `[epic-docs-001] Fix README`)
- **Dependencies** are tracked in the table below, not in the JSONL schema

### Documentation truth rule

- `implemented` / `live` / `deployed` / `shipped` claims require code on the default branch
- Roadmap items must appear under a `Roadmap` heading and reference open issue IDs
- Do not mark a doc feature as implemented until the corresponding issue is `closed` AND code exists

### Dependency table

| Issue ID | Depends on | Scope | Primary files / components |
|----------|-----------|-------|---------------------------|
| `docs-001` | — | grasp-gitea README | `README.md`, `.env.example` |
| `docs-002` | — | fleet-planning spec | `fleet-planning/docs/infrastructure/grasp-gitea-spec.md` |
| `docs-003` | — | fleet-planning services | `fleet-planning/docs/infrastructure/git-services.md` |
| `docs-004` | `docs-002`, `docs-003` | fleet-planning audit | `fleet-planning/docs/audits/grasp-gitea-2026-03-27.md` |
| `phase3-003` | — | E2E verification | `docs/phase3-e2e-checklist.md`, `docs/phase3-e2e-report.md` |
| `phase3-006` | — | config/startup | `internal/config/config.go`, `cmd/grasp-bridge/main.go` |
| `auth-001` | — | auth foundation | `internal/config`, `internal/store`, new auth subsystem |
| `auth-002` | `auth-001` | identity link | `internal/gitea`, auth subsystem |
| `auth-003` | `auth-001`, `auth-002` | NIP-07 flow | auth HTTP endpoints, browser flow |
| `auth-004` | `auth-001`, `auth-002` | NIP-46 flow | remote-signer session, polling |
| `auth-005` | `auth-001`, `auth-002` | NIP-55 flow | challenge/callback, QR/deep-link |
| `auth-006` | `auth-003`, `auth-004`, `auth-005` | hardening | docs, tests, metrics, rollout |
| `publish-001` | — | publisher foundation | webhook handler, signing, relay client |
| `publish-002` | `publish-001` | announcements | provisioner + publisher |
| `publish-003` | `publish-001` | patches | kind 1617, refs/nostr workflow |
| `publish-004` | `publish-001` | PRs | kinds 1618/1619/1630-1633, webhook |
| `publish-005` | `publish-001` | issues/labels | kinds 1621/1985/1630/1632, webhook |
| `publish-006` | `publish-001`, `auth-002` | user lists | kind 10317, identity link |
| `test-001` | — | bridge wiring | `cmd/grasp-bridge`, build tags |
| `test-002` | `phase3-006` | config matrix | `internal/config` |
| `test-003` | — | lifecycle | provision/archive/reconcile/sync |
| `test-004` | `auth-006`, `publish-005` | feature suites | all new subsystems |

---

*Beads: Issue tracking that moves at the speed of thought* ⚡
