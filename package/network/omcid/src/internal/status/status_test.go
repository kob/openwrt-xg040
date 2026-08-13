// SPDX-License-Identifier: Apache-2.0

package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriterPublishesJSONAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "status.json")
	writer := NewWriter(path)
	want := Snapshot{State: "online", Interface: "omci", StartedAt: time.Unix(1, 0).UTC(), RXFrames: 3}
	if err := writer.Write(want); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var got Snapshot
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.State != want.State || got.Interface != want.Interface || got.RXFrames != want.RXFrames {
		t.Fatalf("snapshot = %#v, want %#v", got, want)
	}
}
