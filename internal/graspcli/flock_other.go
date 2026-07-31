// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

//go:build !unix

package graspcli

import "os"

// Non-unix platforms run without an advisory lock; the same-directory
// temp+rename write is still crash-safe, only concurrent grasp processes
// can race each other.
func flockExclusive(*os.File) error { return nil }
func flockRelease(*os.File)         {}
