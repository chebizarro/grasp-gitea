// Copyright 2026 The Grasp Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import "time"

// Gitea webhook payload types

type Repository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

type User struct {
	ID       int64  `json:"id"`
	Login    string `json:"login"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
}

type Commit struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	URL     string `json:"url"`
	Author  struct {
		Name     string    `json:"name"`
		Email    string    `json:"email"`
		Username string    `json:"username"`
		Date     time.Time `json:"date"`
	} `json:"author"`
	Committer struct {
		Name     string    `json:"name"`
		Email    string    `json:"email"`
		Username string    `json:"username"`
		Date     time.Time `json:"date"`
	} `json:"committer"`
	Timestamp time.Time `json:"timestamp"`
}

type PushPayload struct {
	Ref        string     `json:"ref"`
	Before     string     `json:"before"`
	After      string     `json:"after"`
	CompareURL string     `json:"compare_url"`
	Commits    []Commit   `json:"commits"`
	Repository Repository `json:"repository"`
	Pusher     User       `json:"pusher"`
	Sender     User       `json:"sender"`
}

type CreatePayload struct {
	Ref           string     `json:"ref"`
	RefType       string     `json:"ref_type"` // "branch" or "tag"
	DefaultBranch string     `json:"default_branch"`
	Repository    Repository `json:"repository"`
	Sender        User       `json:"sender"`
}

type DeletePayload struct {
	Ref        string     `json:"ref"`
	RefType    string     `json:"ref_type"` // "branch" or "tag"
	PusherType string     `json:"pusher_type"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}

type PullRequest struct {
	ID             int64     `json:"id"`
	Number         int64     `json:"number"`
	User           User      `json:"user"`
	Title          string    `json:"title"`
	Body           string    `json:"body"`
	State          string    `json:"state"` // "open", "closed"
	HTMLURL        string    `json:"html_url"`
	DiffURL        string    `json:"diff_url"`
	PatchURL       string    `json:"patch_url"`
	Mergeable      bool      `json:"mergeable"`
	Merged         bool      `json:"merged"`
	MergedAt       time.Time `json:"merged_at"`
	MergedCommitID string    `json:"merge_commit_sha"`
	MergeBase      string    `json:"merge_base"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ClosedAt       time.Time `json:"closed_at"`
	Head           struct {
		Ref  string     `json:"ref"`
		SHA  string     `json:"sha"`
		Repo Repository `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string     `json:"ref"`
		SHA  string     `json:"sha"`
		Repo Repository `json:"repo"`
	} `json:"base"`
	Draft bool `json:"draft"`
}

type PullRequestPayload struct {
	Action      string      `json:"action"` // "opened", "closed", "reopened", "edited", "synchronized"
	Number      int64       `json:"number"`
	PullRequest PullRequest `json:"pull_request"`
	Repository  Repository  `json:"repository"`
	Sender      User        `json:"sender"`
}

type Issue struct {
	ID        int64     `json:"id"`
	Number    int64     `json:"number"`
	User      User      `json:"user"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"` // "open", "closed"
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ClosedAt  time.Time `json:"closed_at"`
}

type Label struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type IssuePayload struct {
	Action     string     `json:"action"` // "opened", "closed", "reopened", "edited", "labeled", "unlabeled"
	Number     int64      `json:"number"`
	Issue      Issue      `json:"issue"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
	Label      Label      `json:"label"` // Only present for labeled/unlabeled actions
}

type Comment struct {
	ID        int64     `json:"id"`
	HTMLURL   string    `json:"html_url"`
	PRURL     string    `json:"pull_request_url"`
	IssueURL  string    `json:"issue_url"`
	User      User      `json:"user"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type IssueCommentPayload struct {
	Action      string      `json:"action"` // "created", "edited", "deleted"
	Issue       Issue       `json:"issue"`
	PullRequest PullRequest `json:"pull_request"`
	Comment     Comment     `json:"comment"`
	Repository  Repository  `json:"repository"`
	Sender      User        `json:"sender"`
	IsPull      bool        `json:"is_pull"`
}

type LabelPayload struct {
	Action     string     `json:"action"` // "created", "edited", "deleted"
	Label      Label      `json:"label"`
	Repository Repository `json:"repository"`
	Sender     User       `json:"sender"`
}
