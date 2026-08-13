// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	"github.com/xg2010g/airoha-omci/internal/engine"
	platformevent "github.com/xg2010g/airoha-omci/internal/event"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/platform"
	"github.com/xg2010g/airoha-omci/internal/pon"
	"github.com/xg2010g/airoha-omci/internal/software"
	"github.com/xg2010g/airoha-omci/internal/status"
	"github.com/xg2010g/airoha-omci/internal/transaction"
)

var version = "devel"

const transactionQueueCapacity = 1024

type options struct {
	interfaceName    string
	serialNumber     string
	equipmentID      string
	statusPath       string
	statePath        string
	applyHelper      string
	controlHelper    string
	eventHelper      string
	softwareHelper   string
	onu3StatePath    string
	runtimeStatePath string
	restartReason    uint
	ponMode          string
	transportBackend string
	devicePath       string
}

func main() {
	var opts options
	flag.StringVar(&opts.interfaceName, "interface", "omci", "OMCI netdev")
	flag.StringVar(&opts.serialNumber, "serial", "", "ONU serial: four vendor characters and eight hex digits")
	flag.StringVar(&opts.equipmentID, "equipment-id", "XG2010G", "ONU equipment identifier")
	flag.StringVar(&opts.statusPath, "status", "/var/run/airoha-omcid/status.json", "atomic JSON status path")
	flag.StringVar(&opts.statePath, "state", "", "committed platform state used to restore the ONU MIB")
	flag.StringVar(&opts.applyHelper, "apply-helper", "", "fixed executable receiving candidate service graphs as JSON")
	flag.StringVar(&opts.controlHelper, "control-helper", "", "fixed executable handling time sync and scheduled reboot")
	flag.StringVar(&opts.eventHelper, "event-helper", "", "fixed executable streaming platform events as JSON lines")
	flag.StringVar(&opts.softwareHelper, "software-helper", "", "fixed executable handling software image lifecycle")
	flag.StringVar(&opts.onu3StatePath, "onu3-state", "", "persistent platform document used to restore ONU3-G snapshots")
	flag.StringVar(&opts.runtimeStatePath, "runtime-state", "", "persistent alarm, ARC and performance runtime state")
	flag.UintVar(&opts.restartReason, "restart-reason", 0, "G.988 ONU3-G latest restart reason (0..255)")
	flag.StringVar(&opts.ponMode, "pon-mode", string(pon.GPON), "PON protocol mode: gpon or xgspon")
	flag.StringVar(&opts.transportBackend, "transport", "packet", "OMCC transport: packet or device")
	flag.StringVar(&opts.devicePath, "device", "/dev/airoha-xgs-omcc", "secure OMCC character device")
	flag.Parse()

	if err := run(opts); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if opts.restartReason > 0xff {
		return fmt.Errorf("restart reason %d is outside 0..255", opts.restartReason)
	}
	mode, err := pon.ParseMode(opts.ponMode)
	if err != nil {
		return err
	}
	stateDomain, err := mode.StateDomain()
	if err != nil {
		return err
	}
	factory, err := model.XG2010G(model.Identity{
		SerialNumber:  opts.serialNumber,
		Version:       version,
		EquipmentID:   opts.equipmentID,
		RestartReason: uint8(opts.restartReason),
		PONMode:       mode,
	})
	if err != nil {
		return err
	}
	if opts.onu3StatePath != "" {
		restored, restoreErr := restoreONU3Factory(factory, opts.onu3StatePath, stateDomain)
		if restoreErr != nil {
			log.Printf("discard persistent ONU3-G state %s: %v", opts.onu3StatePath, restoreErr)
		} else {
			factory = restored
		}
	}
	var applier mib.Applier
	platformBackend := "memory-only"
	if opts.applyHelper != "" {
		applier = platform.ExecApplier{Path: opts.applyHelper}
		platformBackend = opts.applyHelper
	}
	store, err := initializeMIB(mode, stateDomain, factory, applier, opts.statePath)
	if err != nil {
		return fmt.Errorf("initialize ONU MIB: %w", err)
	}
	var controller engine.Controller
	if opts.controlHelper != "" {
		controller = platform.ExecController{Path: opts.controlHelper}
	}
	var softwareController software.Controller
	softwareBackend := "disabled"
	if opts.softwareHelper != "" {
		softwareController = platform.ExecSoftwareController{Path: opts.softwareHelper}
		softwareBackend = opts.softwareHelper
	}
	protocol := engine.NewForMode(store, controller, softwareController, mode)
	if opts.runtimeStatePath != "" {
		if restoreErr := restoreRuntimeState(protocol, opts.runtimeStatePath); restoreErr != nil {
			log.Printf("discard persistent OMCI runtime state %s: %v",
				opts.runtimeStatePath, restoreErr)
		}
	}
	if err := protocol.RefreshSoftwareImages(); err != nil {
		return fmt.Errorf("load software image state: %w", err)
	}

	conn, err := openTransport(opts)
	if err != nil {
		return err
	}
	defer conn.Close()
	if mode == pon.XGSPON && !conn.Capabilities().SecureOMCC() {
		return errors.New("xgspon mode requires kernel-verified downstream and kernel-signed upstream OMCC")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	started := time.Now().UTC()
	state := status.Snapshot{
		State:           "online",
		Interface:       opts.interfaceName,
		PONMode:         mode,
		StartedAt:       started,
		MIBDataSync:     store.DataSync(),
		MIBEntries:      len(store.Snapshot()),
		PlatformBackend: platformBackend,
		SoftwareBackend: softwareBackend,
	}
	updateSoftwareStatus := func() {
		softwareState := protocol.SoftwareStatus()
		state.SoftwarePhase = softwareState.Phase
		state.SoftwareImageID = softwareState.ImageID
		state.SoftwareBytes = softwareState.Bytes
		state.SoftwareImageSize = softwareState.ImageSize
		state.SoftwareImageHash = softwareState.ImageHash
	}
	updateSoftwareStatus()
	statusWriter := status.NewWriter(opts.statusPath)
	if err := statusWriter.Write(state); err != nil {
		return err
	}
	sendNotifications := func(frames [][]byte) error {
		for _, frame := range frames {
			if err := conn.WriteFrame(ctx, frame); err != nil {
				return err
			}
			state.TXFrames++
			state.NotificationFrames++
			if len(frame) >= 3 {
				state.LastNotificationType = frame[2]
			}
		}
		return nil
	}

	dispatcher, err := transaction.NewDispatcher(ctx, transactionQueueCapacity)
	if err != nil {
		return fmt.Errorf("initialize OMCI transaction queue: %w", err)
	}
	receiveErrors := make(chan error, 1)
	go func() {
		for {
			generation := dispatcher.Generation()
			frame, err := conn.ReadFrame(ctx)
			if err != nil {
				select {
				case receiveErrors <- err:
				case <-ctx.Done():
				}
				return
			}
			if err := dispatcher.Enqueue(ctx, generation, frame); err != nil {
				if ctx.Err() == nil {
					select {
					case receiveErrors <- err:
					case <-ctx.Done():
					}
				}
				return
			}
		}
	}()

	var platformEvents chan platformevent.Event
	var eventSourceErrors chan error
	if opts.eventHelper != "" {
		platformEvents = make(chan platformevent.Event)
		eventSourceErrors = make(chan error, 1)
		go func() {
			err := (platformevent.ExecSource{Path: opts.eventHelper}).Run(ctx,
				func(value platformevent.Event) error {
					select {
					case platformEvents <- value:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			eventSourceErrors <- err
		}()
	}
	arcTicker := time.NewTicker(time.Second)
	defer arcTicker.Stop()
	performanceTicker := time.NewTicker(time.Second)
	defer performanceTicker.Stop()
	multicastTicker := time.NewTicker(time.Second)
	defer multicastTicker.Stop()
	runtimeTicker := time.NewTicker(time.Second)
	defer runtimeTicker.Stop()
	runtimeWriter := newRuntimeStateWriter(opts.runtimeStatePath)
	persistRuntimeState := func() {
		if _, err := runtimeWriter.Write(protocol); err != nil {
			state.EventErrors++
			state.LastError = err.Error()
			_ = statusWriter.Write(state)
			log.Printf("persist OMCI runtime state: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			persistRuntimeState()
			state.State = "stopped"
			_ = statusWriter.Write(state)
			return nil

		case sourceErr := <-eventSourceErrors:
			if ctx.Err() != nil {
				state.State = "stopped"
				_ = statusWriter.Write(state)
				return nil
			}
			state.TransportErrors++
			state.LastError = sourceErr.Error()
			_ = statusWriter.Write(state)
			return sourceErr

		case value := <-platformEvents:
			if value.Type == "omcc-session-reset" {
				if err := dispatcher.Reset(ctx); err != nil {
					if errors.Is(err, context.Canceled) {
						state.State = "stopped"
						_ = statusWriter.Write(state)
						return nil
					}
					state.TransportErrors++
					state.LastError = err.Error()
					_ = statusWriter.Write(state)
					return fmt.Errorf("reset OMCI transaction queue: %w", err)
				}
			}
			frames, err := value.Dispatch(protocol)
			if err != nil {
				state.EventErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				log.Printf("OMCI platform event rejected: %v", err)
				continue
			}
			if err := sendNotifications(frames); err != nil {
				state.TransportErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				return err
			}
			state.MIBDataSync = store.DataSync()
			state.MIBEntries = len(store.Snapshot())
			updateSoftwareStatus()
			state.LastError = ""
			if err := statusWriter.Write(state); err != nil {
				log.Printf("publish status: %v", err)
			}

		case <-arcTicker.C:
			frames, err := protocol.PollARC(omci.BaselineIdent)
			if err != nil {
				state.EventErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				log.Printf("OMCI ARC timer rejected: %v", err)
				continue
			}
			if err := sendNotifications(frames); err != nil {
				state.TransportErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				return err
			}
			if len(frames) != 0 {
				state.MIBDataSync = store.DataSync()
				state.LastError = ""
				if err := statusWriter.Write(state); err != nil {
					log.Printf("publish status: %v", err)
				}
			}

		case <-performanceTicker.C:
			frames, err := protocol.PollPerformance(omci.BaselineIdent)
			if err != nil {
				state.PerformanceErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				log.Printf("OMCI performance collection failed: %v", err)
				continue
			}
			if err := sendNotifications(frames); err != nil {
				state.TransportErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				return err
			}
			if len(frames) != 0 {
				state.LastError = ""
				if err := statusWriter.Write(state); err != nil {
					log.Printf("publish status: %v", err)
				}
			}

		case <-multicastTicker.C:
			if err := protocol.PollMulticast(); err != nil {
				state.EventErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				log.Printf("OMCI multicast timer synchronization failed: %v", err)
				continue
			}

		case <-runtimeTicker.C:
			persistRuntimeState()

		case queueErr := <-dispatcher.Errors():
			state.TransportErrors++
			state.LastError = queueErr.Error()
			_ = statusWriter.Write(state)
			return queueErr

		case receiveErr := <-receiveErrors:
			if receiveErr != nil {
				if errors.Is(receiveErr, context.Canceled) {
					state.State = "stopped"
					_ = statusWriter.Write(state)
					return nil
				}
				state.TransportErrors++
				state.LastError = receiveErr.Error()
				_ = statusWriter.Write(state)
				return receiveErr
			}

		case frame := <-dispatcher.Frames():
			contents := frame.Contents
			state.RXFrames++
			if len(contents) >= 4 {
				state.LastTransactionID = uint16(contents[0])<<8 | uint16(contents[1])
				state.LastMessageType = contents[2]
			}
			response, err := protocol.HandleFrame(engine.DownstreamFrame{
				Contents: contents, MICVerified: frame.MICVerified,
			})
			if err != nil {
				state.DecodeErrors++
				state.LastError = err.Error()
				state.MIBDataSync = store.DataSync()
				state.MIBEntries = len(store.Snapshot())
				updateSoftwareStatus()
				_ = statusWriter.Write(state)
				log.Printf("OMCI request rejected: %v", err)
				continue
			}
			if len(response) != 0 {
				if err := conn.WriteFrame(ctx, response); err != nil {
					state.TransportErrors++
					state.LastError = err.Error()
					_ = statusWriter.Write(state)
					return err
				}
				state.TXFrames++
			}
			if err := sendNotifications(protocol.DrainNotifications()); err != nil {
				state.TransportErrors++
				state.LastError = err.Error()
				_ = statusWriter.Write(state)
				return err
			}
			notificationErr := protocol.DrainNotificationError()
			if notificationErr != nil {
				state.EventErrors++
				state.LastError = notificationErr.Error()
				log.Printf("OMCI derived notification failed: %v", notificationErr)
			}
			state.MIBDataSync = store.DataSync()
			state.MIBEntries = len(store.Snapshot())
			updateSoftwareStatus()
			if notificationErr == nil {
				state.LastError = ""
			}
			if err := statusWriter.Write(state); err != nil {
				log.Printf("publish status: %v", err)
			}
		}
	}
}

type runtimeStateWriter struct {
	path string
	last []byte
}

func newRuntimeStateWriter(path string) *runtimeStateWriter {
	return &runtimeStateWriter{path: path}
}

func (w *runtimeStateWriter) Write(protocol *engine.Engine) (bool, error) {
	if w.path == "" {
		return false, nil
	}
	state, err := protocol.ExportRuntimeState()
	if err != nil {
		return false, fmt.Errorf("export runtime state: %w", err)
	}
	document, err := json.Marshal(state)
	if err != nil {
		return false, fmt.Errorf("encode runtime state: %w", err)
	}
	document = append(document, '\n')
	if bytes.Equal(document, w.last) {
		return false, nil
	}
	if err := writeRuntimeStateAtomic(w.path, document); err != nil {
		return false, err
	}
	w.last = append(w.last[:0], document...)
	return true, nil
}

func restoreRuntimeState(protocol *engine.Engine, path string) error {
	document, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer document.Close()

	decoder := json.NewDecoder(document)
	decoder.DisallowUnknownFields()
	var state engine.RuntimeState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode runtime state: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode runtime state: trailing JSON value")
		}
		return fmt.Errorf("decode runtime state: %w", err)
	}
	return protocol.RestoreRuntimeState(state)
}

func writeRuntimeStateAtomic(path string, document []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create runtime state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".omci-runtime-*")
	if err != nil {
		return fmt.Errorf("create runtime state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect runtime state temporary file: %w", err)
	}
	if _, err := temporary.Write(document); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write runtime state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync runtime state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close runtime state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish runtime state: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open runtime state directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync runtime state directory: %w", err)
	}
	return nil
}

func restoreONU3Factory(factory []mib.Instance, path, stateDomain string) ([]mib.Instance, error) {
	document, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return factory, nil
	}
	if err != nil {
		return nil, err
	}
	defer document.Close()

	request, err := platform.DecodeApplyRequest(document)
	if err != nil {
		return nil, fmt.Errorf("decode persistent platform document: %w", err)
	}
	return mib.RestoreONU3Factory(factory, *request.MIBState, stateDomain)
}

func initializeMIB(mode pon.Mode, stateDomain string, factory []mib.Instance,
	applier mib.Applier, statePath string) (*mib.Store, error) {
	attributeMasks, err := model.XG2010GSupportedAttributeMasks(mode, factory)
	if err != nil {
		return nil, fmt.Errorf("build XG2010G attribute policy: %w", err)
	}
	options := mib.Options{
		Applier:                 applier,
		StateDomain:             stateDomain,
		SupportedClasses:        model.XG2010GSupportedClasses(mode),
		SupportedAttributeMasks: attributeMasks,
		ValidateInstance:        model.XG2010GInstanceValidator(mode),
		AttributeCapabilities:   model.XG2010GAttributeCapabilities(mode),
	}
	if statePath == "" {
		return mib.NewWithOptions(factory, options)
	}

	restoreError := error(nil)
	document, err := os.Open(statePath)
	if err == nil {
		request, decodeErr := platform.DecodeApplyRequest(document)
		closeErr := document.Close()
		if decodeErr != nil {
			restoreError = decodeErr
		} else if closeErr != nil {
			restoreError = closeErr
		} else {
			store, stateErr := mib.NewFromState(factory, *request.MIBState, options)
			if stateErr != nil {
				restoreError = stateErr
			} else {
				graph, graphErr := platform.BuildServiceGraph(store.Snapshot())
				if graphErr != nil {
					restoreError = graphErr
				} else if !reflect.DeepEqual(graph, request.Service) {
					restoreError = fmt.Errorf("persisted service graph does not match restored MIB")
				} else {
					return store, nil
				}
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		restoreError = err
	}
	if restoreError != nil {
		log.Printf("discard committed OMCI state %s: %v", statePath, restoreError)
	}

	store, err := mib.NewWithOptions(factory, options)
	if err != nil {
		return nil, err
	}
	if err := store.Reset(); err != nil {
		return nil, fmt.Errorf("commit factory MIB reset: %w", err)
	}
	return store, nil
}
