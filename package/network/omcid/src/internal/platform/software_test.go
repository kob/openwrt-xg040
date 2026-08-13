// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecSoftwareControllerLifecycle(t *testing.T) {
	directory := t.TempDir()
	payloadPath := filepath.Join(directory, "payload")
	actionsPath := filepath.Join(directory, "actions")
	helper := filepath.Join(directory, "software")
	script := `#!/bin/sh
set -eu
case "$1" in
state)
	printf '%s\n' '{"images":[{"entity_id":0,"version":"old","product_code":"XG2010G","image_hash":"","committed":true,"active":true,"valid":true},{"entity_id":1,"version":"new","product_code":"XG2010G","image_hash":"00112233445566778899aabbccddeeff","committed":false,"active":false,"valid":true}]}'
	;;
download)
	printf 'download %s %s\n' "$2" "$3" >> '` + actionsPath + `'
	cat > '` + payloadPath + `'
	printf '%s\n' '{"version":"new","product_code":"XG2010G"}'
	;;
activate-*|commit-*)
	printf '%s\n' "$*" >> '` + actionsPath + `'
	;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	controller := ExecSoftwareController{Path: helper}
	images, err := controller.Images()
	if err != nil {
		t.Fatalf("Images() error = %v", err)
	}
	if len(images) != 2 || !images[0].Active || images[1].ImageHash[0] != 0x00 ||
		images[1].ImageHash[15] != 0xff {
		t.Fatalf("Images() = %#v", images)
	}
	download, err := controller.Start(1, 7)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := download.Write([]byte("payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	metadata, err := download.Finish()
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if metadata.Version != "new" || metadata.ProductCode != "XG2010G" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if payload, err := os.ReadFile(payloadPath); err != nil || string(payload) != "payload" {
		t.Fatalf("downloaded payload = %q, %v", payload, err)
	}
	activation, err := controller.PrepareActivate(1, 2)
	if err != nil {
		t.Fatalf("PrepareActivate() error = %v", err)
	}
	if err := activation.Commit(); err != nil {
		t.Fatalf("activation Commit() error = %v", err)
	}
	commit, err := controller.PrepareCommit(1)
	if err != nil {
		t.Fatalf("PrepareCommit() error = %v", err)
	}
	if err := commit.Commit(); err != nil {
		t.Fatalf("software Commit() error = %v", err)
	}
	actions, err := os.ReadFile(actionsPath)
	if err != nil {
		t.Fatalf("ReadFile(actions) error = %v", err)
	}
	for _, want := range []string{
		"download 1 7", "activate-prepare 1 2", "activate-commit 1",
		"commit-prepare 1", "commit-commit 1",
	} {
		if !strings.Contains(string(actions), want) {
			t.Fatalf("actions = %q, missing %q", actions, want)
		}
	}
}

func TestExecSoftwareControllerRejectsTrailingJSON(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "software")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"images\":[]}' '{\"extra\":true}'\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecSoftwareController{Path: helper}).Images(); err == nil ||
		!strings.Contains(err.Error(), "trailing") {
		t.Fatalf("Images() error = %v, want trailing JSON error", err)
	}
}

func TestExecSoftwareControllerRejectsMissingCommittedImage(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "software")
	script := `#!/bin/sh
printf '%s\n' '{"images":[{"entity_id":0,"version":"old","product_code":"XG2010G","image_hash":"","committed":false,"active":true,"valid":true},{"entity_id":1,"version":"new","product_code":"XG2010G","image_hash":"","committed":false,"active":false,"valid":true}]}'
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	if _, err := (ExecSoftwareController{Path: helper}).Images(); err == nil ||
		!strings.Contains(err.Error(), "active/committed") {
		t.Fatalf("Images() error = %v, want active/committed state error", err)
	}
}

func TestExecSoftwareControllerAbortsPreparedTransactions(t *testing.T) {
	directory := t.TempDir()
	actionsPath := filepath.Join(directory, "actions")
	helper := filepath.Join(directory, "software")
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> '` + actionsPath + `'
`
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(helper) error = %v", err)
	}
	controller := ExecSoftwareController{Path: helper}
	activation, err := controller.PrepareActivate(1, 2)
	if err != nil {
		t.Fatalf("PrepareActivate() error = %v", err)
	}
	if err := activation.Abort(); err != nil {
		t.Fatalf("activation Abort() error = %v", err)
	}
	commit, err := controller.PrepareCommit(1)
	if err != nil {
		t.Fatalf("PrepareCommit() error = %v", err)
	}
	if err := commit.Abort(); err != nil {
		t.Fatalf("commit Abort() error = %v", err)
	}
	actions, err := os.ReadFile(actionsPath)
	if err != nil {
		t.Fatalf("ReadFile(actions) error = %v", err)
	}
	for _, want := range []string{
		"activate-prepare 1 2", "activate-abort 1",
		"commit-prepare 1", "commit-abort 1",
	} {
		if !strings.Contains(string(actions), want) {
			t.Fatalf("actions = %q, missing %q", actions, want)
		}
	}
}
