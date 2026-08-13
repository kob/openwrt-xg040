// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/checksum"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/software"
)

type softwareDownload struct {
	entityID        uint16
	device          omci.DeviceIdent
	expectedSize    uint32
	received        uint32
	windowSize      uint16
	expectedSection uint8
	window          []byte
	windowFailed    bool
	sink            software.Download
	crc             uint32
	md5             hash.Hash
	phase           softwareDownloadPhase
	end             softwareEndRequest
	finish          <-chan softwareFinishResult
	finished        *softwareFinishResult
	imageHash       [md5.Size]byte
}

type softwareDownloadPhase uint8

const (
	softwareReceiving softwareDownloadPhase = iota
	softwareFinalizing
	softwareComplete
	softwareFailed
)

type softwareEndRequest struct {
	entityID uint16
	device   omci.DeviceIdent
	crc      uint32
	size     uint32
}

type softwareFinishResult struct {
	metadata software.Metadata
	err      error
}

type SoftwareStatus struct {
	Phase     string `json:"phase"`
	ImageID   uint16 `json:"image_id"`
	Bytes     uint32 `json:"bytes"`
	ImageSize uint32 `json:"image_size"`
	ImageHash string `json:"image_hash,omitempty"`
}

func (e *Engine) SoftwareStatus() SoftwareStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.softwareState
}

// RefreshSoftwareImages imports persistent boot-slot state before OMCC
// traffic starts. It does not change MIB data sync because these are
// autonomous ONU attributes.
func (e *Engine) RefreshSoftwareImages() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.software == nil {
		return nil
	}
	images, err := e.software.Images()
	if err != nil {
		return err
	}
	if len(images) != 2 {
		return fmt.Errorf("software backend returned %d images, want 2", len(images))
	}
	seen := make(map[uint16]struct{}, len(images))
	active, committed := 0, 0
	for _, image := range images {
		if image.EntityID > 1 || len(image.Version) > 14 || len(image.ProductCode) > 25 {
			return fmt.Errorf("software backend returned invalid image metadata for %#x", image.EntityID)
		}
		if _, duplicate := seen[image.EntityID]; duplicate {
			return fmt.Errorf("software backend returned duplicate image %#x", image.EntityID)
		}
		seen[image.EntityID] = struct{}{}
		if image.Active {
			active++
		}
		if image.Committed {
			committed++
		}
		if (image.Active || image.Committed) && !image.Valid {
			return fmt.Errorf("software backend returned invalid selected image %#x", image.EntityID)
		}
	}
	if active != 1 || committed != 1 {
		return fmt.Errorf("software backend returned inconsistent image flags")
	}
	for _, image := range images {
		attributes := me.AttributeValueMap{
			me.SoftwareImage_Version:     fixedOctets(image.Version, 14),
			me.SoftwareImage_IsCommitted: boolOctet(image.Committed),
			me.SoftwareImage_IsActive:    boolOctet(image.Active),
			me.SoftwareImage_IsValid:     boolOctet(image.Valid),
			me.SoftwareImage_ProductCode: fixedOctets(image.ProductCode, 25),
			me.SoftwareImage_ImageHash:   append([]byte(nil), image.ImageHash[:]...),
		}
		if _, err := e.mib.UpdateAutonomous(softwareKey(image.EntityID), attributes); err != nil {
			return fmt.Errorf("import software image %#x: %w", image.EntityID, err)
		}
	}
	return nil
}

func (e *Engine) startSoftwareDownload(request *omci.StartSoftwareDownloadRequest,
	device omci.DeviceIdent) me.Results {
	if e.software == nil {
		return me.NotSupported
	}
	if e.softwareDownloadBusy() {
		return me.DeviceBusy
	}
	if request.EntityClass != me.SoftwareImageClassID {
		return me.UnknownEntity
	}
	if request.EntityInstance > 1 {
		return me.UnknownInstance
	}
	if request.ImageSize == 0 || request.NumberOfCircuitPacks != 1 ||
		len(request.CircuitPacks) != 1 || request.CircuitPacks[0] != request.EntityInstance {
		return me.ParameterError
	}
	image, result := e.softwareImage(request.EntityInstance)
	if result != me.Success {
		return result
	}
	if image.active || image.committed {
		return me.ParameterError
	}
	e.download = nil
	sink, err := e.software.Start(request.EntityInstance, request.ImageSize)
	if err != nil {
		return me.ProcessingError
	}
	if err := e.mib.UpdateByCommand(map[mib.Key]me.AttributeValueMap{
		softwareKey(request.EntityInstance): {
			me.SoftwareImage_IsValid: uint8(0),
		},
	}); err != nil {
		_ = sink.Abort()
		return me.ProcessingError
	}
	e.download = &softwareDownload{
		entityID: request.EntityInstance, device: device,
		expectedSize: request.ImageSize, windowSize: uint16(request.WindowSize) + 1,
		sink: sink, crc: checksum.CRC32AInitial, md5: md5.New(), phase: softwareReceiving,
	}
	e.softwareState = SoftwareStatus{
		Phase: "downloading", ImageID: request.EntityInstance, ImageSize: request.ImageSize,
	}
	return me.Success
}

func (e *Engine) downloadSoftwareSection(request *omci.DownloadSectionRequest,
	device omci.DeviceIdent, acknowledged bool) me.Results {
	download := e.download
	if download == nil || download.phase != softwareReceiving {
		return me.ProcessingError
	}
	if request.EntityClass != me.SoftwareImageClassID ||
		request.EntityInstance != download.entityID || device != download.device {
		return me.ParameterError
	}
	if len(request.SectionData) == 0 {
		return e.rejectSoftwareWindow(download, acknowledged, me.ParameterError)
	}
	if download.windowFailed {
		if request.SectionNumber != 0 {
			if acknowledged {
				e.resetSoftwareWindow(download)
				return me.ProcessingError
			}
			return me.Success
		}
		e.resetSoftwareWindow(download)
	}
	if request.SectionNumber != download.expectedSection {
		return e.rejectSoftwareWindow(download, acknowledged, me.ProcessingError)
	}

	remaining := int(download.expectedSize - download.received - uint32(len(download.window)))
	data := request.SectionData
	if len(data) > remaining {
		if device != omci.BaselineIdent || !zeroOctets(data[remaining:]) {
			return e.rejectSoftwareWindow(download, acknowledged, me.ProcessingError)
		}
		data = data[:remaining]
	}
	download.window = append(download.window, data...)

	next := uint16(download.expectedSection) + 1
	if !acknowledged {
		if next >= download.windowSize {
			download.window = nil
			download.windowFailed = true
			download.expectedSection = 0
			return me.Success
		}
		download.expectedSection = uint8(next)
		return me.Success
	}

	if len(download.window) != 0 {
		written, err := download.sink.Write(download.window)
		if err != nil || written != len(download.window) {
			e.failSoftwareDownload()
			return me.ProcessingError
		}
		download.crc = checksum.UpdateCRC32A(download.crc, download.window)
		_, _ = download.md5.Write(download.window)
		download.received += uint32(len(download.window))
	}
	e.resetSoftwareWindow(download)
	e.softwareState.Bytes = download.received
	return me.Success
}

func (e *Engine) endSoftwareDownload(request *omci.EndSoftwareDownloadRequest,
	device omci.DeviceIdent) me.Results {
	download := e.download
	if download == nil {
		return me.ProcessingError
	}
	if request.EntityClass != me.SoftwareImageClassID {
		return me.UnknownEntity
	}
	if request.EntityInstance > 1 {
		return me.UnknownInstance
	}
	if request.EntityInstance != download.entityID || device != download.device {
		return me.ProcessingError
	}
	end := softwareEndRequest{
		entityID: request.EntityInstance, device: device, crc: request.CRC32, size: request.ImageSize,
	}
	if download.phase != softwareReceiving {
		if end != download.end {
			return me.ProcessingError
		}
		return e.softwareFinishStatus(download)
	}
	validRequest := request.ImageSize == download.expectedSize && request.ImageSize == download.received &&
		request.NumberOfInstances == 1 && len(request.ImageInstances) == 1 &&
		request.ImageInstances[0] == download.entityID && len(download.window) == 0 &&
		!download.windowFailed && download.expectedSection == 0
	if !validRequest || request.CRC32 != checksum.SumCRC32A(download.crc) {
		e.failSoftwareDownload()
		return me.ProcessingError
	}

	download.phase = softwareFinalizing
	download.end = end
	copy(download.imageHash[:], download.md5.Sum(nil))
	finished := make(chan softwareFinishResult, 1)
	download.finish = finished
	sink := download.sink
	go func() {
		metadata, err := sink.Finish()
		finished <- softwareFinishResult{metadata: metadata, err: err}
		close(finished)
	}()
	e.softwareState.Phase = "finalizing"
	return me.DeviceBusy
}

func (e *Engine) activateSoftware(request *omci.ActivateSoftwareRequest) me.Results {
	if e.software == nil {
		return me.NotSupported
	}
	if e.softwareDownloadBusy() {
		return me.DeviceBusy
	}
	if request.EntityClass != me.SoftwareImageClassID {
		return me.UnknownEntity
	}
	if request.EntityInstance > 1 {
		return me.UnknownInstance
	}
	image, result := e.softwareImage(request.EntityInstance)
	if result != me.Success {
		return result
	}
	if !image.valid {
		return me.ParameterError
	}
	transaction, err := e.software.PrepareActivate(request.EntityInstance, request.ActivateFlags)
	if err != nil {
		return me.ProcessingError
	}
	if err := e.setExclusiveSoftwareFlag(request.EntityInstance,
		me.SoftwareImage_IsActive, transaction); err != nil {
		return me.ProcessingError
	}
	e.softwareState.Phase = "activating"
	e.softwareState.ImageID = request.EntityInstance
	return me.Success
}

func (e *Engine) commitSoftware(request *omci.CommitSoftwareRequest) me.Results {
	if e.software == nil {
		return me.NotSupported
	}
	if e.softwareDownloadBusy() {
		return me.DeviceBusy
	}
	if request.EntityClass != me.SoftwareImageClassID {
		return me.UnknownEntity
	}
	if request.EntityInstance > 1 {
		return me.UnknownInstance
	}
	image, result := e.softwareImage(request.EntityInstance)
	if result != me.Success {
		return result
	}
	if !image.valid {
		return me.ParameterError
	}
	if image.committed {
		return me.Success
	}
	transaction, err := e.software.PrepareCommit(request.EntityInstance)
	if err != nil {
		return me.ProcessingError
	}
	if err := e.setExclusiveSoftwareFlag(request.EntityInstance,
		me.SoftwareImage_IsCommitted, transaction); err != nil {
		return me.ProcessingError
	}
	e.softwareState.Phase = "committed"
	e.softwareState.ImageID = request.EntityInstance
	return me.Success
}

func (e *Engine) failSoftwareDownload() {
	if e.download != nil && e.download.phase == softwareReceiving {
		_ = e.download.sink.Abort()
	}
	e.download = nil
	e.softwareState.Phase = "failed"
}

func (e *Engine) softwareDownloadBusy() bool {
	return e.download != nil &&
		(e.download.phase == softwareReceiving || e.download.phase == softwareFinalizing)
}

func (e *Engine) softwareFinishStatus(download *softwareDownload) me.Results {
	switch download.phase {
	case softwareComplete:
		return me.Success
	case softwareFailed:
		return me.ProcessingError
	case softwareFinalizing:
	default:
		return me.ProcessingError
	}

	if download.finished == nil {
		select {
		case result := <-download.finish:
			download.finished = &result
		default:
			return me.DeviceBusy
		}
	}
	result := download.finished
	if result.err != nil || len(result.metadata.Version) > 14 || len(result.metadata.ProductCode) > 25 {
		download.phase = softwareFailed
		e.softwareState.Phase = "failed"
		return me.ProcessingError
	}
	if strings.TrimSpace(result.metadata.ProductCode) == "" {
		result.metadata.ProductCode = "XG2010G"
	}
	if err := e.mib.UpdateByCommand(map[mib.Key]me.AttributeValueMap{
		softwareKey(download.entityID): {
			me.SoftwareImage_Version:     fixedOctets(result.metadata.Version, 14),
			me.SoftwareImage_IsValid:     uint8(1),
			me.SoftwareImage_ProductCode: fixedOctets(result.metadata.ProductCode, 25),
			me.SoftwareImage_ImageHash:   append([]byte(nil), download.imageHash[:]...),
		},
	}); err != nil {
		return me.ProcessingError
	}
	download.phase = softwareComplete
	e.softwareState.Phase = "staged"
	e.softwareState.Bytes = download.expectedSize
	e.softwareState.ImageHash = hex.EncodeToString(download.imageHash[:])
	return me.Success
}

func (e *Engine) rejectSoftwareWindow(download *softwareDownload, acknowledged bool,
	result me.Results) me.Results {
	download.window = nil
	download.expectedSection = 0
	if acknowledged {
		download.windowFailed = false
		return result
	}
	download.windowFailed = true
	return me.Success
}

func (e *Engine) resetSoftwareWindow(download *softwareDownload) {
	download.window = nil
	download.windowFailed = false
	download.expectedSection = 0
}

func zeroOctets(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}

type imageFlags struct {
	active    bool
	committed bool
	valid     bool
}

func (e *Engine) softwareImage(entityID uint16) (imageFlags, me.Results) {
	instance, err := e.mib.Get(softwareKey(entityID), 0x7000)
	result, _, _ := operationResult(err)
	if result != me.Success {
		return imageFlags{}, result
	}
	active, activeOK := instance.Attributes[me.SoftwareImage_IsActive].(uint8)
	committed, committedOK := instance.Attributes[me.SoftwareImage_IsCommitted].(uint8)
	valid, validOK := instance.Attributes[me.SoftwareImage_IsValid].(uint8)
	if !activeOK || !committedOK || !validOK {
		return imageFlags{}, me.ProcessingError
	}
	return imageFlags{active: active == 1, committed: committed == 1, valid: valid == 1}, me.Success
}

func (e *Engine) setExclusiveSoftwareFlag(selected uint16, attribute string,
	transaction software.Transaction) error {
	updates := make(map[mib.Key]me.AttributeValueMap, 2)
	for entityID := uint16(0); entityID <= 1; entityID++ {
		value := uint8(0)
		if entityID == selected {
			value = 1
		}
		updates[softwareKey(entityID)] = me.AttributeValueMap{
			attribute: value,
		}
	}
	return e.mib.UpdateByCommandTransactional(updates, transaction)
}

func softwareKey(entityID uint16) mib.Key {
	return mib.Key{ClassID: me.SoftwareImageClassID, EntityID: entityID}
}

func boolOctet(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func fixedOctets(value string, size int) []byte {
	result := make([]byte, size)
	copy(result, strings.TrimSpace(value))
	return result
}
