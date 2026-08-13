// SPDX-License-Identifier: Apache-2.0

package transaction

import (
	"context"
	"errors"
	"testing"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	"github.com/xg2010g/airoha-omci/internal/transport"
)

func TestFrameQueuePrioritizesBaselineHighAndRetainsFIFO(t *testing.T) {
	queue, err := newFrameQueue(5)
	if err != nil {
		t.Fatalf("newFrameQueue() error = %v", err)
	}
	frames := []transport.Frame{
		frame(1, omci.BaselineIdent),
		frame(0x8002, omci.ExtendedIdent),
		frame(3, omci.BaselineIdent),
		frame(0x8004, omci.BaselineIdent),
		frame(0x8005, omci.BaselineIdent),
	}
	for _, value := range frames {
		if err := queue.push(value); err != nil {
			t.Fatalf("push(%#x) error = %v", transactionID(value), err)
		}
	}
	want := []uint16{0x8004, 0x8005, 1, 0x8002, 3}
	for _, id := range want {
		if got := transactionID(queue.peek()); got != id {
			t.Fatalf("peek() transaction = %#x, want %#x", got, id)
		}
		queue.pop()
	}
	if queue.peek().Contents != nil || queue.length() != 0 {
		t.Fatalf("drained queue length = %d, peek = %+v", queue.length(), queue.peek())
	}
}

func TestFrameQueuePreservesTrustedMetadataAndOwnsContents(t *testing.T) {
	queue, err := newFrameQueue(1)
	if err != nil {
		t.Fatal(err)
	}
	input := frame(1, omci.BaselineIdent)
	input.MICVerified = true
	if err := queue.push(input); err != nil {
		t.Fatal(err)
	}
	input.Contents[0] = 0xff
	queued := queue.peek()
	if !queued.MICVerified || transactionID(queued) != 1 {
		t.Fatalf("queued frame=%+v", queued)
	}
}

func TestFrameQueueCapacityAndOwnership(t *testing.T) {
	queue, err := newFrameQueue(1)
	if err != nil {
		t.Fatalf("newFrameQueue() error = %v", err)
	}
	value := frame(1, omci.BaselineIdent)
	if err := queue.push(value); err != nil {
		t.Fatalf("push() error = %v", err)
	}
	value.Contents[0] = 0xff
	if got := transactionID(queue.peek()); got != 1 {
		t.Fatalf("queued transaction = %#x, want 1", got)
	}
	if err := queue.push(frame(2, omci.BaselineIdent)); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full push error = %v, want ErrQueueFull", err)
	}
	if queue.length() != 1 {
		t.Fatalf("queue length after rejected push = %d, want 1", queue.length())
	}
}

func TestDispatcherResetDropsQueuedAndInFlightOldSessionFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher, err := NewDispatcher(ctx, 8)
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	oldGeneration := dispatcher.Generation()
	if err := dispatcher.Enqueue(ctx, oldGeneration, frame(1, omci.BaselineIdent)); err != nil {
		t.Fatalf("Enqueue(old queued) error = %v", err)
	}
	if err := dispatcher.Reset(ctx); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if dispatcher.Generation() == oldGeneration {
		t.Fatal("Reset() did not advance generation")
	}
	if err := dispatcher.Enqueue(ctx, oldGeneration, frame(0x8002, omci.BaselineIdent)); err != nil {
		t.Fatalf("Enqueue(old in-flight) error = %v", err)
	}
	if err := dispatcher.Enqueue(ctx, dispatcher.Generation(), frame(3, omci.BaselineIdent)); err != nil {
		t.Fatalf("Enqueue(current) error = %v", err)
	}
	select {
	case got := <-dispatcher.Frames():
		if id := transactionID(got); id != 3 {
			t.Fatalf("dispatched transaction = %#x, want 3", id)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for current-session frame")
	}
}

func TestDispatcherReportsQueueExhaustion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher, err := NewDispatcher(ctx, 1)
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	generation := dispatcher.Generation()
	if err := dispatcher.Enqueue(ctx, generation, frame(1, omci.BaselineIdent)); err != nil {
		t.Fatalf("Enqueue(first) error = %v", err)
	}
	if err := dispatcher.Enqueue(ctx, generation, frame(2, omci.BaselineIdent)); err != nil {
		t.Fatalf("Enqueue(overflow) error = %v", err)
	}
	select {
	case err := <-dispatcher.Errors():
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("dispatcher error = %v, want ErrQueueFull", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for queue exhaustion")
	}
}

func TestDispatcherRejectsInvalidCapacity(t *testing.T) {
	if _, err := NewDispatcher(context.Background(), 0); err == nil {
		t.Fatal("NewDispatcher(0) error = nil")
	}
}

func frame(transactionID uint16, device omci.DeviceIdent) transport.Frame {
	return transport.Frame{Contents: []byte{
		byte(transactionID >> 8), byte(transactionID), 0, byte(device),
	}}
}

func transactionID(frame transport.Frame) uint16 {
	return uint16(frame.Contents[0])<<8 | uint16(frame.Contents[1])
}
