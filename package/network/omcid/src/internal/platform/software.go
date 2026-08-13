// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/xg2010g/airoha-omci/internal/software"
)

type ExecSoftwareController struct {
	Path    string
	Timeout time.Duration
}

type imageStateResponse struct {
	Images []struct {
		EntityID    uint16 `json:"entity_id"`
		Version     string `json:"version"`
		ProductCode string `json:"product_code"`
		ImageHash   string `json:"image_hash"`
		Committed   bool   `json:"committed"`
		Active      bool   `json:"active"`
		Valid       bool   `json:"valid"`
	} `json:"images"`
}

func (c ExecSoftwareController) Images() ([]software.Image, error) {
	output, err := c.execute("state")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var response imageStateResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decode software image state: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode software image state: %w", err)
	}
	if len(response.Images) != 2 {
		return nil, fmt.Errorf("software helper returned %d images, want 2", len(response.Images))
	}
	images := make([]software.Image, 0, len(response.Images))
	seen := make(map[uint16]struct{}, len(response.Images))
	active, committed := 0, 0
	for _, value := range response.Images {
		if value.EntityID > 1 {
			return nil, fmt.Errorf("software helper returned invalid image ID %#x", value.EntityID)
		}
		if _, duplicate := seen[value.EntityID]; duplicate {
			return nil, fmt.Errorf("software helper returned duplicate image ID %#x", value.EntityID)
		}
		seen[value.EntityID] = struct{}{}
		var hash [16]byte
		if value.ImageHash != "" {
			decoded, err := hex.DecodeString(value.ImageHash)
			if err != nil || len(decoded) != len(hash) {
				return nil, fmt.Errorf("software image %#x has invalid MD5 hash", value.EntityID)
			}
			copy(hash[:], decoded)
		}
		if value.Active {
			active++
		}
		if value.Committed {
			committed++
		}
		if (value.Active || value.Committed) && !value.Valid {
			return nil, fmt.Errorf("software helper returned invalid selected image %#x", value.EntityID)
		}
		images = append(images, software.Image{
			EntityID: value.EntityID, Version: value.Version,
			ProductCode: value.ProductCode, ImageHash: hash,
			Committed: value.Committed, Active: value.Active, Valid: value.Valid,
		})
	}
	if active != 1 || committed != 1 {
		return nil, fmt.Errorf("software helper returned invalid active/committed image state")
	}
	return images, nil
}

func (c ExecSoftwareController) Start(entityID uint16, imageSize uint32) (software.Download, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("software helper is empty")
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, c.Path, "download",
		strconv.FormatUint(uint64(entityID), 10), strconv.FormatUint(uint64(imageSize), 10))
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open software helper input: %w", err)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		cancel()
		return nil, fmt.Errorf("start software helper: %w", err)
	}
	return &execDownload{
		command: command, stdin: stdin, cancel: cancel,
		stdout: &stdout, stderr: &stderr, timeout: c.timeout(),
	}, nil
}

func (c ExecSoftwareController) PrepareActivate(entityID uint16,
	flags uint8) (software.Transaction, error) {
	id := strconv.FormatUint(uint64(entityID), 10)
	if _, err := c.execute("activate-prepare", id,
		strconv.FormatUint(uint64(flags), 10)); err != nil {
		return nil, err
	}
	return &execSoftwareTransaction{
		controller: c, commitArguments: []string{"activate-commit", id},
		abortArguments: []string{"activate-abort", id},
	}, nil
}

func (c ExecSoftwareController) PrepareCommit(entityID uint16) (software.Transaction, error) {
	id := strconv.FormatUint(uint64(entityID), 10)
	if _, err := c.execute("commit-prepare", id); err != nil {
		return nil, err
	}
	return &execSoftwareTransaction{
		controller: c, commitArguments: []string{"commit-commit", id},
		abortArguments: []string{"commit-abort", id},
	}, nil
}

type execSoftwareTransaction struct {
	mu              sync.Mutex
	controller      ExecSoftwareController
	commitArguments []string
	abortArguments  []string
	done            bool
}

func (t *execSoftwareTransaction) Commit() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil
	}
	if _, err := t.controller.execute(t.commitArguments...); err != nil {
		return err
	}
	t.done = true
	return nil
}

func (t *execSoftwareTransaction) Abort() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil
	}
	if _, err := t.controller.execute(t.abortArguments...); err != nil {
		return err
	}
	t.done = true
	return nil
}

func (c ExecSoftwareController) execute(arguments ...string) ([]byte, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("software helper is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout())
	defer cancel()
	command := exec.CommandContext(ctx, c.Path, arguments...)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("software helper timed out after %s: %w", c.timeout(), ctx.Err())
	}
	if err != nil {
		return nil, commandError("software helper", err, output)
	}
	return output, nil
}

func (c ExecSoftwareController) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 2 * time.Minute
	}
	return c.Timeout
}

type execDownload struct {
	mu      sync.Mutex
	command *exec.Cmd
	stdin   io.WriteCloser
	cancel  context.CancelFunc
	stdout  *bytes.Buffer
	stderr  *bytes.Buffer
	timeout time.Duration
	done    bool
}

func (d *execDownload) Write(value []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return 0, fmt.Errorf("software download is closed")
	}
	return d.stdin.Write(value)
}

func (d *execDownload) Finish() (software.Metadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return software.Metadata{}, fmt.Errorf("software download is closed")
	}
	d.done = true
	if err := d.stdin.Close(); err != nil {
		d.cancel()
		_ = d.command.Wait()
		return software.Metadata{}, fmt.Errorf("close software helper input: %w", err)
	}
	err := d.wait()
	d.cancel()
	if err != nil {
		return software.Metadata{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(d.stdout.Bytes()))
	decoder.DisallowUnknownFields()
	var metadata software.Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return software.Metadata{}, fmt.Errorf("decode software helper result: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return software.Metadata{}, fmt.Errorf("decode software helper result: %w", err)
	}
	return metadata, nil
}

func (d *execDownload) Abort() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return nil
	}
	d.done = true
	_ = d.stdin.Close()
	d.cancel()
	if err := d.command.Wait(); err != nil {
		if d.command.ProcessState != nil && d.command.ProcessState.Exited() {
			return nil
		}
		return err
	}
	return nil
}

func (d *execDownload) wait() error {
	done := make(chan error, 1)
	go func() { done <- d.command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return commandError("software download helper", err, d.stderr.Bytes())
		}
		return nil
	case <-time.After(d.timeout):
		d.cancel()
		err := <-done
		if err == nil {
			return fmt.Errorf("software download helper timed out after %s", d.timeout)
		}
		return fmt.Errorf("software download helper timed out after %s: %w", d.timeout, err)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func commandError(prefix string, err error, output []byte) error {
	detail := string(bytes.TrimSpace(output))
	if detail == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, detail)
}
