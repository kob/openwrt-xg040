// SPDX-License-Identifier: Apache-2.0

package status

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/xg2010g/airoha-omci/internal/pon"
)

type Snapshot struct {
	State                string    `json:"state"`
	Interface            string    `json:"interface"`
	PONMode              pon.Mode  `json:"pon_mode"`
	StartedAt            time.Time `json:"started_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	MIBDataSync          uint8     `json:"mib_data_sync"`
	MIBEntries           int       `json:"mib_entries"`
	PlatformBackend      string    `json:"platform_backend"`
	SoftwareBackend      string    `json:"software_backend"`
	SoftwarePhase        string    `json:"software_phase"`
	SoftwareImageID      uint16    `json:"software_image_id"`
	SoftwareBytes        uint32    `json:"software_bytes"`
	SoftwareImageSize    uint32    `json:"software_image_size"`
	SoftwareImageHash    string    `json:"software_image_hash,omitempty"`
	RXFrames             uint64    `json:"rx_frames"`
	TXFrames             uint64    `json:"tx_frames"`
	DecodeErrors         uint64    `json:"decode_errors"`
	TransportErrors      uint64    `json:"transport_errors"`
	EventErrors          uint64    `json:"event_errors"`
	PerformanceErrors    uint64    `json:"performance_errors"`
	NotificationFrames   uint64    `json:"notification_frames"`
	LastTransactionID    uint16    `json:"last_transaction_id"`
	LastMessageType      uint8     `json:"last_message_type"`
	LastNotificationType uint8     `json:"last_notification_type"`
	LastError            string    `json:"last_error,omitempty"`
}

type Writer struct {
	path string
}

func NewWriter(path string) *Writer {
	return &Writer{path: path}
}

func (w *Writer) Write(snapshot Snapshot) error {
	snapshot.UpdatedAt = time.Now().UTC()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode OMCI status: %w", err)
	}
	encoded = append(encoded, '\n')

	directory := filepath.Dir(w.path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create OMCI status directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".omci-status-*")
	if err != nil {
		return fmt.Errorf("create OMCI status temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write OMCI status: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close OMCI status: %w", err)
	}
	if err := os.Rename(temporaryPath, w.path); err != nil {
		return fmt.Errorf("publish OMCI status: %w", err)
	}
	return nil
}
