// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 OuterSpace OS contributors
// Injected into containerd/pkg/oci for the source-bound compatibility test.
package oci

import (
	"bytes"
	"io"
	"testing"
	"testing/fstest"

	"github.com/moby/sys/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moby/sys/user v0.4.1 intentionally caps a group line at 1 MiB. The original
// containerd test expects a line near 10 MiB to parse and is no longer valid.
func TestOuterSpaceGroupParserBound(t *testing.T) {
	t.Run("below parser limit", func(t *testing.T) {
		data := append(bytes.Repeat([]byte{0}, 900_000), []byte("\nbeyond:x:42:\n")...)
		root := fstest.MapFS{"etc/group": &fstest.MapFile{Data: data, Mode: 0o644}}
		gids, err := getSupplementalGroupsFromFS(root, func(g user.Group) bool { return g.Name == "beyond" })
		require.NoError(t, err)
		assert.Equal(t, []uint32{42}, gids)
	})
	t.Run("overlong line is rejected", func(t *testing.T) {
		data := append(bytes.Repeat([]byte{0}, 1<<20), []byte("\nbeyond:x:42:\n")...)
		root := fstest.MapFS{"etc/group": &fstest.MapFile{Data: data, Mode: 0o644}}
		_, err := getSupplementalGroupsFromFS(root, func(g user.Group) bool { return g.Name == "beyond" })
		assert.ErrorContains(t, err, "token too long")
	})
}

func TestOuterSpaceUserFileOverallLimit(t *testing.T) {
	root := fstest.MapFS{"etc/group": &fstest.MapFile{Data: make([]byte, maxUserFileBytes+1), Mode: 0o644}}
	f, err := openUserFile(root, "etc/group")
	require.NoError(t, err)
	defer f.Close()
	_, err = io.ReadAll(f)
	assert.ErrorContains(t, err, "exceeds")
}
