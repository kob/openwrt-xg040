// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xg2010g/airoha-omci/internal/multicast"
)

func TestPublishMonitorsIncludesVersionedAllowedPreviewTimers(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	runtime, err := multicast.NewRuntime(multicast.Config{
		Profiles: []multicast.Profile{{EntityID: 0x700, IGMPVersion: 2}},
		Subscribers: []multicast.Subscriber{{
			EntityID: 0x500, Profile: 0x700,
			Attachments: []multicast.Attachment{{Interface: "lan1", BridgeEntity: 0x100}},
			AllowedPreviews: []multicast.AllowedPreview{{
				RowKey: 7, Destination: netip.MustParseAddr("239.1.2.3"),
				Duration: 60, TimeLeft: 23,
			}},
		}},
	}, nil, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	directory := t.TempDir()
	if err := publishMonitors(directory, runtime, 17); err != nil {
		t.Fatalf("publishMonitors() error = %v", err)
	}
	payload, err := os.ReadFile(filepath.Join(directory, "1280.json"))
	if err != nil {
		t.Fatalf("ReadFile(monitor) error = %v", err)
	}
	var document monitorDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("Unmarshal(monitor) error = %v", err)
	}
	if document.SubscriberID != 0x500 || document.MIBDataSync != 17 ||
		len(document.AllowedPreviews) != 1 ||
		document.AllowedPreviews[0] != (previewTimer{RowKey: 7, Duration: 60, TimeLeft: 23}) {
		t.Fatalf("monitor document = %+v", document)
	}
}
