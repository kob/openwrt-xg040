// SPDX-License-Identifier: Apache-2.0

package transaction

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	omci "github.com/opencord/omci-lib-go/v2"
	"github.com/xg2010g/airoha-omci/internal/transport"
)

var ErrQueueFull = errors.New("OMCI transaction queue is full")

type queuedFrame struct {
	generation uint64
	frame      transport.Frame
}

type frameQueue struct {
	capacity int
	high     []transport.Frame
	normal   []transport.Frame
}

func newFrameQueue(capacity int) (*frameQueue, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("OMCI transaction queue capacity must be positive")
	}
	return &frameQueue{capacity: capacity}, nil
}

func (q *frameQueue) push(frame transport.Frame) error {
	if q.length() >= q.capacity {
		return fmt.Errorf("%w: capacity %d", ErrQueueFull, q.capacity)
	}
	frame = cloneFrame(frame)
	if isBaselineHighPriority(frame) {
		q.high = append(q.high, frame)
	} else {
		q.normal = append(q.normal, frame)
	}
	return nil
}

func (q *frameQueue) peek() transport.Frame {
	if len(q.high) != 0 {
		return q.high[0]
	}
	if len(q.normal) != 0 {
		return q.normal[0]
	}
	return transport.Frame{}
}

func (q *frameQueue) pop() {
	if len(q.high) != 0 {
		q.high[0] = transport.Frame{}
		q.high = q.high[1:]
		if len(q.high) == 0 {
			q.high = nil
		}
		return
	}
	if len(q.normal) != 0 {
		q.normal[0] = transport.Frame{}
		q.normal = q.normal[1:]
		if len(q.normal) == 0 {
			q.normal = nil
		}
	}
}

func (q *frameQueue) clear() {
	clear(q.high)
	clear(q.normal)
	q.high = nil
	q.normal = nil
}

func (q *frameQueue) length() int {
	return len(q.high) + len(q.normal)
}

func cloneFrame(frame transport.Frame) transport.Frame {
	frame.Contents = append([]byte(nil), frame.Contents...)
	return frame
}

func isBaselineHighPriority(frame transport.Frame) bool {
	contents := frame.Contents
	return len(contents) >= 4 && omci.DeviceIdent(contents[3]) == omci.BaselineIdent &&
		binary.BigEndian.Uint16(contents[:2])&0x8000 != 0
}

// Dispatcher drains the OMCC receive path while the protocol engine is busy.
// Baseline high-priority transactions are delivered before baseline low and
// extended transactions, with FIFO ordering retained within each class.
type Dispatcher struct {
	ingress    chan queuedFrame
	reset      chan chan uint64
	frames     chan transport.Frame
	errors     chan error
	generation atomic.Uint64
}

func NewDispatcher(ctx context.Context, capacity int) (*Dispatcher, error) {
	queue, err := newFrameQueue(capacity)
	if err != nil {
		return nil, err
	}
	dispatcher := &Dispatcher{
		ingress: make(chan queuedFrame),
		reset:   make(chan chan uint64),
		frames:  make(chan transport.Frame),
		errors:  make(chan error, 1),
	}
	go dispatcher.run(ctx, queue)
	return dispatcher, nil
}

// Generation returns the current OMCC session generation. The caller obtains
// it before starting a blocking receive and supplies it to Enqueue.
func (d *Dispatcher) Generation() uint64 {
	return d.generation.Load()
}

func (d *Dispatcher) Enqueue(ctx context.Context, generation uint64, frame transport.Frame) error {
	item := queuedFrame{generation: generation, frame: cloneFrame(frame)}
	select {
	case d.ingress <- item:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Reset atomically drops queued frames and advances the session generation.
// A receive that started before Reset is discarded even if it completes later.
func (d *Dispatcher) Reset(ctx context.Context) error {
	acknowledged := make(chan uint64, 1)
	select {
	case d.reset <- acknowledged:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-acknowledged:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Dispatcher) Frames() <-chan transport.Frame {
	return d.frames
}

func (d *Dispatcher) Errors() <-chan error {
	return d.errors
}

func (d *Dispatcher) run(ctx context.Context, queue *frameQueue) {
	var generation uint64
	d.generation.Store(generation)

	for {
		var output chan transport.Frame
		var next transport.Frame
		if queue.length() != 0 {
			output = d.frames
			next = queue.peek()
		}

		select {
		case <-ctx.Done():
			return
		case acknowledged := <-d.reset:
			generation++
			queue.clear()
			d.generation.Store(generation)
			acknowledged <- generation
		case item := <-d.ingress:
			if item.generation != generation {
				continue
			}
			if err := queue.push(item.frame); err != nil {
				select {
				case d.errors <- err:
				case <-ctx.Done():
				}
				return
			}
		case output <- next:
			queue.pop()
		}
	}
}
