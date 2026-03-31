// Package webhook handles inbound Gitea webhook events and maps them to NIP-34 Nostr events.
package webhook

// PushPayload is sent by Gitea on push events.
type PushPayload struct {
	Ref        string     `json:"ref"`        // e.g. "refs/heads/main"
	Before     string     `json:"before"`
	After      string     `json:"after"`
	Repository Repository `json:"repository"`
	Pusher     User       `json:"pusher"`
	Commits    []Commit   `json:"commits"`
}

// CreatePayload is sent on branch/tag creation.
type CreatePayload struct {
	Ref        string     `json:"ref"`
	RefType    string     `json:"ref_type"` // "branch" or "tag"
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}

// DeletePayload is sent on branch/tag deletion.
type DeletePayload struct {
	Ref        string     `json:"ref"`
	RefType    string     `json:"ref_type"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}

// PullRequestPayload is sent on PR open/update/close/merge.
type PullRequestPayload struct {
	Action      string      `json:"action"` // "opened","edited","closed","reopened","synchronized","labeled","unlabeled","assigned","unassigned","milestoned","demilestoned","review_requested","review_request_removed"
	Number      int64       `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Sender      User        `json:"sender"`
	Review      *Review     `json:"review,omitempty"`
}

// IssuePayload is sent on issue open/close/edit/label changes.
type IssuePayload struct {
	Action     string     `json:"action"` // "opened","edited","deleted","transferred","pinned","unpinned","closed","reopened","labeled","unlabeled","milestoned","demilestoned","assigned","unassigned"
	Index      int64      `json:"index"`
	Issue      Issue      `json:"issue"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}

// IssueCommentPayload is sent on issue comment events.
type IssueCommentPayload struct {
	Action     string     `json:"action"`
	Issue      Issue      `json:"issue"`
	Comment    Comment    `json:"comment"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}

// Repository is the Gitea repo object embedded in webhook payloads.
type Repository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
	Owner         User   `json:"owner"`
	Private       bool   `json:"private"`
}

type User struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	URL     string `json:"url"`
}

type PullRequest struct {
	ID             int64  `json:"id"`
	Number         int64  `json:"number"`
	Title          string `json:"title"`
	Body           string `json:"body"`
	State          string `json:"state"` // "open","closed"
	HTMLURL        string `json:"html_url"`
	DiffURL        string `json:"diff_url"`
	PatchURL       string `json:"patch_url"`
	Head           PRRef  `json:"head"`
	Base           PRRef  `json:"base"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	User           User   `json:"user"`
}

type PRRef struct {
	Label  string     `json:"label"`
	Ref    string     `json:"ref"`
	SHA    string     `json:"sha"`
	Repo   Repository `json:"repo"`
}

type Issue struct {
	ID      int64  `json:"id"`
	Number  int64  `json:"number"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	State   string `json:"state"` // "open","closed"
	HTMLURL string `json:"html_url"`
	User    User   `json:"user"`
}

type Comment struct {
	ID      int64  `json:"id"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	User    User   `json:"user"`
}

type Review struct {
	Type string `json:"type"`
}

// Label maps a Gitea label object.
type Label struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}
