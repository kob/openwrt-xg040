// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const maxEventLineSize = 64 * 1024

type ExecSource struct {
	Path string
}

// Run starts a fixed-path helper and consumes one JSON event per stdout line.
// The helper is terminated with the supplied context. No shell is involved.
func (source ExecSource) Run(ctx context.Context, handle func(Event) error) error {
	if source.Path == "" {
		return fmt.Errorf("platform event helper is empty")
	}
	command := exec.CommandContext(ctx, source.Path)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open platform event stream: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start platform event helper: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxEventLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		event, err := Decode([]byte(line))
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
		if err := handle(event); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return fmt.Errorf("read platform event stream: %w", err)
	}
	err = command.Wait()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("platform event helper exited: %w", err)
	}
	return fmt.Errorf("platform event helper exited unexpectedly")
}
