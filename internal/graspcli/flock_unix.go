// Copyright 2026 Sharegap contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

//go:build unix

package graspcli

import (
	"os"

	"golang.org/x/sys/unix"
)

func flockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func flockRelease(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
