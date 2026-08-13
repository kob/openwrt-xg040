// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"crypto/md5"
	"errors"
	"runtime"
	"testing"
	"time"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/checksum"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/pon"
	"github.com/xg2010g/airoha-omci/internal/software"
)

type recordingSoftwareController struct {
	images            []software.Image
	download          *recordingDownload
	startedID         uint16
	startedSize       uint32
	activatedID       uint16
	activateFlags     uint8
	committedID       uint16
	startCalls        int
	activateCalls     int
	commitCalls       int
	activateAborts    int
	commitAborts      int
	activateCommitErr error
	commitCommitErr   error
	finishGate        <-chan struct{}
}

func (c *recordingSoftwareController) Images() ([]software.Image, error) {
	return append([]software.Image(nil), c.images...), nil
}

func (c *recordingSoftwareController) Start(entityID uint16, imageSize uint32) (software.Download, error) {
	c.startCalls++
	c.startedID = entityID
	c.startedSize = imageSize
	c.download = &recordingDownload{finishGate: c.finishGate}
	return c.download, nil
}

func (c *recordingSoftwareController) PrepareActivate(entityID uint16,
	flags uint8) (software.Transaction, error) {
	return &recordingSoftwareTransaction{
		commit: func() error {
			c.activateCalls++
			c.activatedID = entityID
			c.activateFlags = flags
			return c.activateCommitErr
		},
		abort: func() error {
			c.activateAborts++
			return nil
		},
	}, nil
}

func (c *recordingSoftwareController) PrepareCommit(entityID uint16) (software.Transaction, error) {
	return &recordingSoftwareTransaction{
		commit: func() error {
			c.commitCalls++
			c.committedID = entityID
			return c.commitCommitErr
		},
		abort: func() error {
			c.commitAborts++
			return nil
		},
	}, nil
}

type recordingSoftwareTransaction struct {
	commit func() error
	abort  func() error
}

func (t *recordingSoftwareTransaction) Commit() error { return t.commit() }
func (t *recordingSoftwareTransaction) Abort() error  { return t.abort() }

type recordingDownload struct {
	bytes.Buffer
	finished   bool
	aborted    bool
	finishGate <-chan struct{}
}

func (d *recordingDownload) Finish() (software.Metadata, error) {
	if d.finishGate != nil {
		<-d.finishGate
	}
	d.finished = true
	return software.Metadata{Version: "2026.08", ProductCode: "XG2010G"}, nil
}

func (d *recordingDownload) Abort() error {
	d.aborted = true
	return nil
}

func TestSoftwareDownloadLifecycleAndNoResponseReplay(t *testing.T) {
	protocol, store, controller := newSoftwareTestEngine(t)
	if _, err := store.UpdateAutonomous(softwareKey(1), me.AttributeValueMap{
		me.SoftwareImage_IsValid: uint8(1),
	}); err != nil {
		t.Fatalf("mark standby image valid: %v", err)
	}
	image := make([]byte, 35)
	for index := range image {
		image[index] = byte(index + 1)
	}

	start := encodeRequest(t, 20, omci.StartSoftwareDownloadRequestType, &omci.StartSoftwareDownloadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		WindowSize:   1, ImageSize: uint32(len(image)), NumberOfCircuitPacks: 1,
		CircuitPacks: []uint16{1},
	})
	encoded, err := protocol.Handle(start)
	if err != nil {
		t.Fatalf("Handle(StartSoftwareDownload) error = %v", err)
	}
	startResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeStartSoftwareDownloadResponse).(*omci.StartSoftwareDownloadResponse)
	if startResponse.Result != me.Success || startResponse.NumberOfInstances != 0 || len(startResponse.MeResults) != 0 ||
		controller.startedID != 1 || controller.startedSize != uint32(len(image)) {
		t.Fatalf("start response/controller = %#v %#v", startResponse, controller)
	}
	if store.DataSync() != 1 {
		t.Fatalf("MIB data sync after StartSoftwareDownload = %d, want 1", store.DataSync())
	}

	firstSection := encodeRequest(t, 21, omci.DownloadSectionRequestType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 0, SectionData: image[:omci.MaxDownloadSectionLength],
	})
	if encoded, err = protocol.Handle(firstSection); err != nil || encoded != nil {
		t.Fatalf("Handle(no-response section) = %x, %v; want nil, nil", encoded, err)
	}
	if encoded, err = protocol.Handle(firstSection); err != nil || encoded != nil {
		t.Fatalf("Handle(duplicate no-response section) = %x, %v; want nil, nil", encoded, err)
	}
	if got := controller.download.Len(); got != 0 {
		t.Fatalf("unacknowledged window wrote %d bytes before its ACK", got)
	}

	lastSection := encodeRequest(t, 22, omci.DownloadSectionRequestWithResponseType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 1, SectionData: image[omci.MaxDownloadSectionLength:],
	})
	encoded, err = protocol.Handle(lastSection)
	if err != nil {
		t.Fatalf("Handle(last section) error = %v", err)
	}
	sectionResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
	if sectionResponse.Result != me.Success || !bytes.Equal(controller.download.Bytes(), image) {
		t.Fatalf("last section result/data = %v/%x", sectionResponse.Result, controller.download.Bytes())
	}

	endRequest := &omci.EndSoftwareDownloadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		CRC32:        checksum.CRC32A(image), ImageSize: uint32(len(image)),
		NumberOfInstances: 1, ImageInstances: []uint16{1},
	}
	end := encodeRequest(t, 23, omci.EndSoftwareDownloadRequestType, endRequest)
	encoded, err = protocol.Handle(end)
	if err != nil {
		t.Fatalf("Handle(EndSoftwareDownload) error = %v", err)
	}
	endResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeEndSoftwareDownloadResponse).(*omci.EndSoftwareDownloadResponse)
	if endResponse.Result != me.DeviceBusy || endResponse.NumberOfInstances != 0 || len(endResponse.MeResults) != 0 {
		t.Fatalf("initial end response = %#v, want device busy", endResponse)
	}
	if store.DataSync() != 1 {
		t.Fatalf("MIB data sync while finalizing = %d, want 1", store.DataSync())
	}
	endResponse = waitForEndSoftwareDownload(t, protocol, endRequest, 26)
	if endResponse.Result != me.Success || !controller.download.finished {
		t.Fatalf("final end response/finished = %#v/%v", endResponse, controller.download.finished)
	}
	if store.DataSync() != 2 {
		t.Fatalf("MIB data sync after EndSoftwareDownload = %d, want 2", store.DataSync())
	}
	instance, err := store.Get(softwareKey(1), 0xfc00)
	if err != nil {
		t.Fatalf("Get(software image) error = %v", err)
	}
	wantHash := md5.Sum(image)
	if instance.Attributes[me.SoftwareImage_IsValid] != uint8(1) ||
		!bytes.Equal(instance.Attributes[me.SoftwareImage_ImageHash].([]byte), wantHash[:]) {
		t.Fatalf("software image attributes = %#v", instance.Attributes)
	}

	activate := encodeRequest(t, 24, omci.ActivateSoftwareRequestType, &omci.ActivateSoftwareRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		ActivateFlags: 2,
	})
	encoded, err = protocol.Handle(activate)
	if err != nil {
		t.Fatalf("Handle(ActivateSoftware) error = %v", err)
	}
	if response := decodeResponse(t, encoded).Layer(omci.LayerTypeActivateSoftwareResponse).(*omci.ActivateSoftwareResponse); response.Result != me.Success || controller.activatedID != 1 || controller.activateFlags != 2 {
		t.Fatalf("activate response/controller = %#v/%#v", response, controller)
	}
	if store.DataSync() != 3 {
		t.Fatalf("MIB data sync after ActivateSoftware = %d, want 3", store.DataSync())
	}

	commit := encodeRequest(t, 25, omci.CommitSoftwareRequestType, &omci.CommitSoftwareRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
	})
	encoded, err = protocol.Handle(commit)
	if err != nil {
		t.Fatalf("Handle(CommitSoftware) error = %v", err)
	}
	if response := decodeResponse(t, encoded).Layer(omci.LayerTypeCommitSoftwareResponse).(*omci.CommitSoftwareResponse); response.Result != me.Success || controller.committedID != 1 {
		t.Fatalf("commit response/controller = %#v/%#v", response, controller)
	}
	if store.DataSync() != 4 {
		t.Fatalf("MIB data sync after CommitSoftware = %d, want 4", store.DataSync())
	}
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsActive, 0)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsActive, 1)
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsCommitted, 0)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsCommitted, 1)
}

func TestActivateSoftwareCommitFailureAbortsAndRestoresMIB(t *testing.T) {
	protocol, store, controller, changes := newTransactionalSoftwareTestEngine(t)
	if _, err := store.UpdateAutonomous(softwareKey(1), me.AttributeValueMap{
		me.SoftwareImage_IsValid: uint8(1),
	}); err != nil {
		t.Fatalf("mark standby image valid: %v", err)
	}
	controller.activateCommitErr = errors.New("activation commit failed")
	request := encodeRequest(t, 27, omci.ActivateSoftwareRequestType,
		&omci.ActivateSoftwareRequest{
			MeBasePacket: omci.MeBasePacket{
				EntityClass: me.SoftwareImageClassID, EntityInstance: 1,
			},
		})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(ActivateSoftware) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeActivateSoftwareResponse).(*omci.ActivateSoftwareResponse)
	if response.Result != me.ProcessingError || controller.activateCalls != 1 ||
		controller.activateAborts != 1 || len(*changes) != 2 {
		t.Fatalf("failed activation response/controller/changes = %#v/%#v/%d",
			response, controller, len(*changes))
	}
	if store.DataSync() != 0 {
		t.Fatalf("failed activation advanced MIB data sync to %d", store.DataSync())
	}
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsActive, 1)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsActive, 0)
}

func TestCommitSoftwarePlatformFailureAbortsAndRestoresMIB(t *testing.T) {
	protocol, store, controller, changes := newTransactionalSoftwareTestEngine(t)
	if _, err := store.UpdateAutonomous(softwareKey(1), me.AttributeValueMap{
		me.SoftwareImage_IsValid: uint8(1),
	}); err != nil {
		t.Fatalf("mark standby image valid: %v", err)
	}
	controller.commitCommitErr = errors.New("software commit failed")
	request := encodeRequest(t, 28, omci.CommitSoftwareRequestType,
		&omci.CommitSoftwareRequest{MeBasePacket: omci.MeBasePacket{
			EntityClass: me.SoftwareImageClassID, EntityInstance: 1,
		}})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(CommitSoftware) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeCommitSoftwareResponse).(*omci.CommitSoftwareResponse)
	if response.Result != me.ProcessingError || controller.commitCalls != 1 ||
		controller.commitAborts != 1 || len(*changes) != 2 {
		t.Fatalf("failed commit response/controller/changes = %#v/%#v/%d",
			response, controller, len(*changes))
	}
	if store.DataSync() != 0 {
		t.Fatalf("failed commit advanced MIB data sync to %d", store.DataSync())
	}
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsCommitted, 1)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsCommitted, 0)
}

func TestSoftwareDownloadRetriesOutOfOrderWindowWithoutAborting(t *testing.T) {
	protocol, _, controller := newSoftwareTestEngine(t)
	start := encodeRequest(t, 30, omci.StartSoftwareDownloadRequestType, &omci.StartSoftwareDownloadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		WindowSize:   3, ImageSize: 31, NumberOfCircuitPacks: 1, CircuitPacks: []uint16{1},
	})
	if _, err := protocol.Handle(start); err != nil {
		t.Fatalf("Handle(StartSoftwareDownload) error = %v", err)
	}
	section := encodeRequest(t, 31, omci.DownloadSectionRequestWithResponseType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 1, SectionData: make([]byte, 31),
	})
	encoded, err := protocol.Handle(section)
	if err != nil {
		t.Fatalf("Handle(out-of-order section) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
	if response.Result != me.ProcessingError || controller.download.aborted || controller.download.Len() != 0 {
		t.Fatalf("section result/aborted/bytes = %v/%v/%d", response.Result,
			controller.download.aborted, controller.download.Len())
	}
	retry := encodeRequest(t, 32, omci.DownloadSectionRequestWithResponseType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 0, SectionData: make([]byte, 31),
	})
	encoded, err = protocol.Handle(retry)
	if err != nil {
		t.Fatalf("Handle(retried window) error = %v", err)
	}
	response = decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
	if response.Result != me.Success || controller.download.Len() != 31 || controller.download.aborted {
		t.Fatalf("retry result/bytes/aborted = %v/%d/%v", response.Result,
			controller.download.Len(), controller.download.aborted)
	}
}

func TestSoftwareDownloadAcceptsShortWindowsAndBaselinePadding(t *testing.T) {
	protocol, _, controller := newSoftwareTestEngine(t)
	image := make([]byte, 70)
	for index := range image {
		image[index] = byte(index + 1)
	}
	startSoftwareTestDownload(t, protocol, uint32(len(image)), 3, 40)

	for _, section := range []struct {
		transaction uint16
		message     omci.MessageType
		number      uint8
		data        []byte
	}{
		{41, omci.DownloadSectionRequestType, 0, image[:31]},
		{42, omci.DownloadSectionRequestWithResponseType, 1, image[31:62]},
		{43, omci.DownloadSectionRequestWithResponseType, 0, image[62:]},
	} {
		encoded, err := protocol.Handle(encodeRequest(t, section.transaction, section.message,
			&omci.DownloadSectionRequest{
				MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
				SectionNumber: section.number, SectionData: section.data,
			}))
		if err != nil {
			t.Fatalf("Handle(section %d) error = %v", section.number, err)
		}
		if section.message == omci.DownloadSectionRequestWithResponseType {
			response := decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
			if response.Result != me.Success {
				t.Fatalf("section %d result = %v", section.number, response.Result)
			}
		}
	}
	if !bytes.Equal(controller.download.Bytes(), image) {
		t.Fatalf("downloaded image = %x, want %x", controller.download.Bytes(), image)
	}
}

func TestSoftwareDownloadRejectsNonZeroBaselinePaddingAndRetriesWindow(t *testing.T) {
	protocol, _, controller := newSoftwareTestEngine(t)
	image := make([]byte, 35)
	for index := range image {
		image[index] = byte(index + 1)
	}
	startSoftwareTestDownload(t, protocol, uint32(len(image)), 1, 50)
	first := encodeRequest(t, 51, omci.DownloadSectionRequestWithResponseType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 0, SectionData: image[:31],
	})
	if encoded, err := protocol.Handle(first); err != nil ||
		decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse).Result != me.Success {
		t.Fatalf("Handle(first window) = %x, %v", encoded, err)
	}

	badLast := make([]byte, omci.MaxDownloadSectionLength)
	copy(badLast, image[31:])
	badLast[4] = 0xff
	encoded, err := protocol.Handle(encodeRequest(t, 52, omci.DownloadSectionRequestWithResponseType,
		&omci.DownloadSectionRequest{
			MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
			SectionNumber: 0, SectionData: badLast,
		}))
	if err != nil {
		t.Fatalf("Handle(non-zero padding) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
	if response.Result != me.ProcessingError || controller.download.Len() != 31 || controller.download.aborted {
		t.Fatalf("padding result/bytes/aborted = %v/%d/%v", response.Result,
			controller.download.Len(), controller.download.aborted)
	}

	encoded, err = protocol.Handle(encodeRequest(t, 53, omci.DownloadSectionRequestWithResponseType,
		&omci.DownloadSectionRequest{
			MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
			SectionNumber: 0, SectionData: image[31:],
		}))
	if err != nil {
		t.Fatalf("Handle(retried final window) error = %v", err)
	}
	response = decodeResponse(t, encoded).Layer(omci.LayerTypeDownloadSectionResponse).(*omci.DownloadSectionResponse)
	if response.Result != me.Success || !bytes.Equal(controller.download.Bytes(), image) {
		t.Fatalf("retry result/image = %v/%x", response.Result, controller.download.Bytes())
	}
}

func TestEndSoftwareDownloadReturnsBusyUntilPersistentFinish(t *testing.T) {
	protocol, store, controller := newSoftwareTestEngine(t)
	gate := make(chan struct{})
	controller.finishGate = gate
	image := bytes.Repeat([]byte{0x5a}, 31)
	startSoftwareTestDownload(t, protocol, uint32(len(image)), 0, 60)
	section := encodeRequest(t, 61, omci.DownloadSectionRequestWithResponseType, &omci.DownloadSectionRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		SectionNumber: 0, SectionData: image,
	})
	if _, err := protocol.Handle(section); err != nil {
		t.Fatalf("Handle(section) error = %v", err)
	}
	endRequest := &omci.EndSoftwareDownloadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		CRC32:        checksum.CRC32A(image), ImageSize: uint32(len(image)),
		NumberOfInstances: 1, ImageInstances: []uint16{1},
	}
	end := encodeRequest(t, 62, omci.EndSoftwareDownloadRequestType, endRequest)
	encoded, err := protocol.Handle(end)
	if err != nil {
		t.Fatalf("Handle(first EndSoftwareDownload) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeEndSoftwareDownloadResponse).(*omci.EndSoftwareDownloadResponse).Result; result != me.DeviceBusy {
		t.Fatalf("first EndSoftwareDownload result = %v, want device busy", result)
	}
	encoded, err = protocol.Handle(encodeRequest(t, 63, omci.EndSoftwareDownloadRequestType, endRequest))
	if err != nil {
		t.Fatalf("Handle(busy EndSoftwareDownload retry) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeEndSoftwareDownloadResponse).(*omci.EndSoftwareDownloadResponse).Result; result != me.DeviceBusy {
		t.Fatalf("busy EndSoftwareDownload retry result = %v", result)
	}
	if store.DataSync() != 0 || protocol.SoftwareStatus().Phase != "finalizing" {
		t.Fatalf("finalizing data sync/status = %d/%#v", store.DataSync(), protocol.SoftwareStatus())
	}
	close(gate)
	response := waitForEndSoftwareDownload(t, protocol, endRequest, 64)
	if response.Result != me.Success || store.DataSync() != 1 || protocol.SoftwareStatus().Phase != "staged" {
		t.Fatalf("final EndSoftwareDownload result/data sync/status = %v/%d/%#v",
			response.Result, store.DataSync(), protocol.SoftwareStatus())
	}

	encoded, err = protocol.Handle(encodeRequest(t, 100, omci.EndSoftwareDownloadRequestType, endRequest))
	if err != nil {
		t.Fatalf("Handle(completed EndSoftwareDownload retry) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeEndSoftwareDownloadResponse).(*omci.EndSoftwareDownloadResponse).Result; result != me.Success {
		t.Fatalf("completed EndSoftwareDownload retry result = %v", result)
	}
	if store.DataSync() != 1 {
		t.Fatalf("completed EndSoftwareDownload retry changed data sync to %d", store.DataSync())
	}
}

func TestSoftwareImageActionStateRules(t *testing.T) {
	protocol, store, controller := newSoftwareTestEngine(t)
	if _, err := store.UpdateAutonomous(softwareKey(1), me.AttributeValueMap{
		me.SoftwareImage_IsValid: uint8(1),
	}); err != nil {
		t.Fatalf("mark image 1 valid: %v", err)
	}

	activate := encodeRequest(t, 110, omci.ActivateSoftwareRequestType, &omci.ActivateSoftwareRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 0},
	})
	encoded, err := protocol.Handle(activate)
	if err != nil {
		t.Fatalf("Handle(activate active image) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeActivateSoftwareResponse).(*omci.ActivateSoftwareResponse).Result; result != me.Success || controller.activateCalls != 1 || controller.activatedID != 0 {
		t.Fatalf("activate active image result/controller = %v/%#v", result, controller)
	}
	if store.DataSync() != 0 {
		t.Fatalf("restarting active image changed MIB data sync to %d", store.DataSync())
	}

	commit := encodeRequest(t, 111, omci.CommitSoftwareRequestType, &omci.CommitSoftwareRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
	})
	encoded, err = protocol.Handle(commit)
	if err != nil {
		t.Fatalf("Handle(commit inactive image) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeCommitSoftwareResponse).(*omci.CommitSoftwareResponse).Result; result != me.Success || controller.commitCalls != 1 || controller.committedID != 1 {
		t.Fatalf("commit inactive image result/controller = %v/%#v", result, controller)
	}
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsCommitted, 0)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsCommitted, 1)

	start := encodeRequest(t, 112, omci.StartSoftwareDownloadRequestType, &omci.StartSoftwareDownloadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
		ImageSize:    31, NumberOfCircuitPacks: 1, CircuitPacks: []uint16{1},
	})
	encoded, err = protocol.Handle(start)
	if err != nil {
		t.Fatalf("Handle(start committed inactive image) error = %v", err)
	}
	if result := decodeResponse(t, encoded).Layer(omci.LayerTypeStartSoftwareDownloadResponse).(*omci.StartSoftwareDownloadResponse).Result; result != me.ParameterError || controller.startCalls != 0 {
		t.Fatalf("start committed inactive image result/start calls = %v/%d", result, controller.startCalls)
	}
}

func TestSoftwareDownloadReportsUnsupportedParallelTargetAsUnknownInstance(t *testing.T) {
	protocol, _, controller := newSoftwareTestEngine(t)
	request := encodeRequest(t, 120, omci.StartSoftwareDownloadRequestType,
		&omci.StartSoftwareDownloadRequest{
			MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 0xffff},
			ImageSize:    31, NumberOfCircuitPacks: 2, CircuitPacks: []uint16{0, 1},
		})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(parallel StartSoftwareDownload) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeStartSoftwareDownloadResponse).(*omci.StartSoftwareDownloadResponse)
	if response.Result != me.UnknownInstance || response.NumberOfInstances != 0 ||
		len(response.MeResults) != 0 || controller.startCalls != 0 {
		t.Fatalf("parallel start response/controller = %#v/%#v", response, controller)
	}
}

func TestRefreshSoftwareImagesImportsPersistentFlags(t *testing.T) {
	protocol, store, controller := newSoftwareTestEngine(t)
	controller.images = []software.Image{
		{EntityID: 0, Version: "old", ProductCode: "XG2010G", Valid: true},
		{EntityID: 1, Version: "new", ProductCode: "XG2010G", Active: true, Committed: true, Valid: true},
	}
	if err := protocol.RefreshSoftwareImages(); err != nil {
		t.Fatalf("RefreshSoftwareImages() error = %v", err)
	}
	assertSoftwareFlag(t, store, 0, me.SoftwareImage_IsActive, 0)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsActive, 1)
	assertSoftwareFlag(t, store, 1, me.SoftwareImage_IsCommitted, 1)
	if store.DataSync() != 0 {
		t.Fatalf("RefreshSoftwareImages changed MIB data sync to %d", store.DataSync())
	}
}

func TestRefreshSoftwareImagesRejectsInvalidSelectedImage(t *testing.T) {
	protocol, _, controller := newSoftwareTestEngine(t)
	controller.images = []software.Image{
		{EntityID: 0, Version: "bad", ProductCode: "XG2010G", Active: true, Committed: true},
		{EntityID: 1, Version: "new", ProductCode: "XG2010G", Valid: true},
	}
	if err := protocol.RefreshSoftwareImages(); err == nil {
		t.Fatal("RefreshSoftwareImages() accepted invalid active/committed image")
	}
}

func newSoftwareTestEngine(t *testing.T) (*Engine, *mib.Store, *recordingSoftwareController) {
	t.Helper()
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", Version: "old", PONMode: pon.GPON})
	if err != nil {
		t.Fatalf("model.XG2010G() error = %v", err)
	}
	store, err := mib.New(factory)
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	controller := &recordingSoftwareController{}
	return NewWithControllers(store, nil, controller), store, controller
}

func newTransactionalSoftwareTestEngine(t *testing.T) (*Engine, *mib.Store,
	*recordingSoftwareController, *[]mib.Change) {
	t.Helper()
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", Version: "old", PONMode: pon.GPON})
	if err != nil {
		t.Fatalf("model.XG2010G() error = %v", err)
	}
	changes := make([]mib.Change, 0, 2)
	store, err := mib.NewWithApplier(factory, mib.ApplyFunc(func(change mib.Change) error {
		changes = append(changes, change)
		return nil
	}))
	if err != nil {
		t.Fatalf("mib.NewWithApplier() error = %v", err)
	}
	controller := &recordingSoftwareController{}
	return NewWithControllers(store, nil, controller), store, controller, &changes
}

func startSoftwareTestDownload(t *testing.T, protocol *Engine, size uint32, windowSize uint8,
	transactionID uint16) {
	t.Helper()
	encoded, err := protocol.Handle(encodeRequest(t, transactionID, omci.StartSoftwareDownloadRequestType,
		&omci.StartSoftwareDownloadRequest{
			MeBasePacket: omci.MeBasePacket{EntityClass: me.SoftwareImageClassID, EntityInstance: 1},
			WindowSize:   windowSize, ImageSize: size, NumberOfCircuitPacks: 1, CircuitPacks: []uint16{1},
		}))
	if err != nil {
		t.Fatalf("Handle(StartSoftwareDownload) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeStartSoftwareDownloadResponse).(*omci.StartSoftwareDownloadResponse)
	if response.Result != me.Success {
		t.Fatalf("StartSoftwareDownload result = %v", response.Result)
	}
}

func waitForEndSoftwareDownload(t *testing.T, protocol *Engine, request *omci.EndSoftwareDownloadRequest,
	transactionID uint16) *omci.EndSoftwareDownloadResponse {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		encoded, err := protocol.Handle(encodeRequest(t, transactionID,
			omci.EndSoftwareDownloadRequestType, request))
		if err != nil {
			t.Fatalf("Handle(EndSoftwareDownload retry) error = %v", err)
		}
		response := decodeResponse(t, encoded).Layer(omci.LayerTypeEndSoftwareDownloadResponse).(*omci.EndSoftwareDownloadResponse)
		if response.Result != me.DeviceBusy {
			return response
		}
		transactionID++
		runtime.Gosched()
	}
	t.Fatal("EndSoftwareDownload remained busy")
	return nil
}

func assertSoftwareFlag(t *testing.T, store *mib.Store, entityID uint16, attribute string, want uint8) {
	t.Helper()
	instance, err := store.Get(softwareKey(entityID), 0x7000)
	if err != nil {
		t.Fatalf("Get(software image %#x) error = %v", entityID, err)
	}
	if got := instance.Attributes[attribute]; got != want {
		t.Fatalf("software image %#x %s = %#v, want %d", entityID, attribute, got, want)
	}
}
