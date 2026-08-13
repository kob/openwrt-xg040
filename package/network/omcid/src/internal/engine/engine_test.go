// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	omci "github.com/opencord/omci-lib-go/v2"
	me "github.com/opencord/omci-lib-go/v2/generated"
	"github.com/xg2010g/airoha-omci/internal/checksum"
	"github.com/xg2010g/airoha-omci/internal/mib"
	"github.com/xg2010g/airoha-omci/internal/model"
	"github.com/xg2010g/airoha-omci/internal/optical"
	"github.com/xg2010g/airoha-omci/internal/pon"
)

func TestCreateDuplicateIsReplayedWithoutDoubleMutation(t *testing.T) {
	engine, store := newTestEngine(t)
	request := encodeRequest(t, 1, omci.CreateRequestType, &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: 1,
		},
		Attributes: me.AttributeValueMap{
			me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
		},
	})

	first, err := engine.Handle(request)
	if err != nil {
		t.Fatalf("Handle(first) error = %v", err)
	}
	second, err := engine.Handle(request)
	if err != nil {
		t.Fatalf("Handle(duplicate) error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("duplicate response differs from original")
	}
	if got := store.DataSync(); got != 1 {
		t.Fatalf("DataSync() = %d, want 1", got)
	}

	packet := decodeResponse(t, first)
	response := packet.Layer(omci.LayerTypeCreateResponse).(*omci.CreateResponse)
	if response.Result != me.Success {
		t.Fatalf("Create result = %v, want success", response.Result)
	}
}

func TestBaselineReplayUsesLastTCIPerPriority(t *testing.T) {
	protocol, store := newTestEngine(t)
	low := encodeRequest(t, 0x0042, omci.CreateRequestType, &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: 1,
		},
		Attributes: me.AttributeValueMap{
			me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
		},
	})
	first, err := protocol.Handle(low)
	if err != nil {
		t.Fatalf("Handle(low priority) error = %v", err)
	}

	sameTCI := encodeRequest(t, 0x0042, omci.CreateRequestType, &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: 2,
		},
		Attributes: me.AttributeValueMap{
			me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
		},
	})
	replayed, err := protocol.Handle(sameTCI)
	if err != nil {
		t.Fatalf("Handle(same low-priority TCI) error = %v", err)
	}
	if string(replayed) != string(first) || store.Exists(mib.Key{
		ClassID: me.GalEthernetProfileClassID, EntityID: 2,
	}) {
		t.Fatal("same low-priority TCI was executed instead of replayed")
	}

	high := encodeRequest(t, 0x8042, omci.CreateRequestType, &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: 2,
		},
		Attributes: me.AttributeValueMap{
			me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
		},
	})
	encoded, err := protocol.Handle(high)
	if err != nil {
		t.Fatalf("Handle(high priority) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeCreateResponse).(*omci.CreateResponse)
	if response.Result != me.Success || !store.Exists(mib.Key{
		ClassID: me.GalEthernetProfileClassID, EntityID: 2,
	}) || store.DataSync() != 2 {
		t.Fatalf("independent high-priority transaction failed: result=%v sync=%d",
			response.Result, store.DataSync())
	}
}

func TestOnlyLastTransactionInPriorityClassIsReplayed(t *testing.T) {
	protocol, store := newTestEngine(t)
	create := func(tci, entityID uint16) []byte {
		return encodeRequest(t, tci, omci.CreateRequestType, &omci.CreateRequest{
			MeBasePacket: omci.MeBasePacket{
				EntityClass:    me.GalEthernetProfileClassID,
				EntityInstance: entityID,
			},
			Attributes: me.AttributeValueMap{
				me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
			},
		})
	}

	first := create(1, 1)
	if _, err := protocol.Handle(first); err != nil {
		t.Fatalf("Handle(first transaction) error = %v", err)
	}
	if _, err := protocol.Handle(create(2, 2)); err != nil {
		t.Fatalf("Handle(second transaction) error = %v", err)
	}
	encoded, err := protocol.Handle(first)
	if err != nil {
		t.Fatalf("Handle(expired transaction ID) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeCreateResponse).(*omci.CreateResponse)
	if response.Result != me.InstanceExists || store.DataSync() != 2 {
		t.Fatalf("expired transaction replay result=%v sync=%d, want InstanceExists/2",
			response.Result, store.DataSync())
	}
}

func TestExtendedReplayUsesSinglePriorityClass(t *testing.T) {
	protocol, store := newTestEngine(t)
	create := func(entityID uint16) []byte {
		return encodeRequestForDevice(t, 0x8042, omci.CreateRequestType, &omci.CreateRequest{
			MeBasePacket: omci.MeBasePacket{
				EntityClass:    me.GalEthernetProfileClassID,
				EntityInstance: entityID,
				Extended:       true,
			},
			Attributes: me.AttributeValueMap{
				me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
			},
		}, omci.ExtendedIdent)
	}

	first, err := protocol.Handle(create(1))
	if err != nil {
		t.Fatalf("Handle(first extended transaction) error = %v", err)
	}
	replayed, err := protocol.Handle(create(2))
	if err != nil {
		t.Fatalf("Handle(reused extended TCI) error = %v", err)
	}
	if string(replayed) != string(first) || store.Exists(mib.Key{
		ClassID: me.GalEthernetProfileClassID, EntityID: 2,
	}) || store.DataSync() != 1 {
		t.Fatal("extended TCI was not replayed in the single priority class")
	}
}

func TestFrameBoundsAllowAdapterTrailerModes(t *testing.T) {
	baseline := make([]byte, omci.MaxBaselineLength)
	baseline[3] = byte(omci.BaselineIdent)
	binary.BigEndian.PutUint32(baseline[omci.MaxBaselineLength-4:],
		checksum.CRC32A(baseline[:omci.MaxBaselineLength-4]))
	extended := make([]byte, 15)
	extended[3] = byte(omci.ExtendedIdent)
	binary.BigEndian.PutUint16(extended[8:10], 5)
	extendedWithMIC := append(append([]byte(nil), extended...), make([]byte, 4)...)
	binary.BigEndian.PutUint32(extendedWithMIC[len(extended):], checksum.CRC32A(extended))

	for name, frame := range map[string][]byte{
		"baseline with trailer":    baseline,
		"baseline without MIC":     baseline[:omci.MaxBaselineLength-4],
		"baseline without trailer": baseline[:omci.MaxBaselineLength-8],
		"extended with MIC":        extendedWithMIC,
		"extended without MIC":     extended,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateFrame(pon.GPON, DownstreamFrame{Contents: frame}); err != nil {
				t.Fatalf("validateFrame() error = %v", err)
			}
		})
	}

	for name, frame := range map[string][]byte{
		"short header":          make([]byte, 3),
		"unknown device":        append([]byte{0, 1, byte(omci.GetRequestType), 0xff}, make([]byte, 44)...),
		"short baseline":        baseline[:39],
		"trailing baseline":     append(append([]byte(nil), baseline...), 0),
		"short extended header": []byte{0, 1, byte(omci.GetRequestType), byte(omci.ExtendedIdent)},
		"truncated extended":    extended[:14],
		"trailing extended":     append(append([]byte(nil), extended...), 0),
		"oversized extended":    append([]byte{0, 1, byte(omci.GetRequestType), byte(omci.ExtendedIdent)}, make([]byte, omci.MaxExtendedLength-3)...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateFrame(pon.GPON, DownstreamFrame{Contents: frame}); err == nil {
				t.Fatal("validateFrame() accepted malformed frame")
			}
		})
	}
}

func TestFrameBoundsRejectInvalidGPONMIC(t *testing.T) {
	baseline := make([]byte, omci.MaxBaselineLength)
	baseline[3] = byte(omci.BaselineIdent)
	binary.BigEndian.PutUint32(baseline[omci.MaxBaselineLength-4:],
		checksum.CRC32A(baseline[:omci.MaxBaselineLength-4]))
	baseline[7] ^= 1

	extended := make([]byte, 19)
	extended[3] = byte(omci.ExtendedIdent)
	binary.BigEndian.PutUint16(extended[8:10], 5)
	binary.BigEndian.PutUint32(extended[15:], checksum.CRC32A(extended[:15]))
	extended[18] ^= 1

	for name, frame := range map[string][]byte{
		"baseline": baseline,
		"extended": extended,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateFrame(pon.GPON, DownstreamFrame{Contents: frame}); err == nil {
				t.Fatal("validateFrame() accepted an invalid GPON MIC")
			}
		})
	}
}

func TestXGSPONFrameValidationRequiresTrustedMICMetadata(t *testing.T) {
	baseline := make([]byte, omci.MaxBaselineLength-8)
	baseline[3] = byte(omci.BaselineIdent)
	if err := validateFrame(pon.XGSPON, DownstreamFrame{Contents: baseline}); err == nil ||
		!strings.Contains(err.Error(), "trusted MIC") {
		t.Fatalf("unverified XGS-PON baseline error = %v", err)
	}
	if err := validateFrame(pon.XGSPON, DownstreamFrame{
		Contents: baseline, MICVerified: true,
	}); err != nil {
		t.Fatalf("verified, stripped XGS-PON baseline error = %v", err)
	}
	withTrailer := append(append([]byte(nil), baseline...), make([]byte, 8)...)
	if err := validateFrame(pon.XGSPON, DownstreamFrame{
		Contents: withTrailer, MICVerified: true,
	}); err == nil || !strings.Contains(err.Error(), "did not remove") {
		t.Fatalf("XGS-PON frame retaining trailer error = %v", err)
	}
}

func TestMibResetAndUpload(t *testing.T) {
	engine, store := newTestEngine(t)
	if err := store.Create(me.GalEthernetProfileClassID, 1, me.AttributeValueMap{
		me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
	}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	reset := encodeRequest(t, 2, omci.MibResetRequestType, &omci.MibResetRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID},
	})
	if _, err := engine.Handle(reset); err != nil {
		t.Fatalf("Handle(MIB reset) error = %v", err)
	}
	if got := store.DataSync(); got != 0 {
		t.Fatalf("DataSync() = %d, want 0", got)
	}

	upload := encodeRequest(t, 3, omci.MibUploadRequestType, &omci.MibUploadRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID},
	})
	encoded, err := engine.Handle(upload)
	if err != nil {
		t.Fatalf("Handle(MIB upload) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeMibUploadResponse).(*omci.MibUploadResponse)
	if response.NumberOfCommands != 1 {
		t.Fatalf("NumberOfCommands = %d, want 1", response.NumberOfCommands)
	}

	next := encodeRequest(t, 4, omci.MibUploadNextRequestType, &omci.MibUploadNextRequest{
		MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		CommandSequenceNumber: 0,
	})
	encoded, err = engine.Handle(next)
	if err != nil {
		t.Fatalf("Handle(MIB upload next) error = %v", err)
	}
	nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeMibUploadNextResponse).(*omci.MibUploadNextResponse)
	if nextResponse.ReportedME.GetClassID() != me.OnuDataClassID {
		t.Fatalf("reported class = %v, want ONU data", nextResponse.ReportedME.GetClassID())
	}
}

func TestCompleteXG2010GFactoryMIBUpload(t *testing.T) {
	factory, err := model.XG2010G(model.Identity{SerialNumber: "TEST01020304", PONMode: pon.GPON})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := model.XG2010GSupportedAttributeMasks(pon.GPON, factory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := mib.NewWithOptions(factory, mib.Options{
		SupportedClasses:        model.XG2010GSupportedClasses(pon.GPON),
		SupportedAttributeMasks: masks,
		ValidateInstance:        model.XG2010GInstanceValidator(pon.GPON),
		AttributeCapabilities:   model.XG2010GAttributeCapabilities(pon.GPON),
	})
	if err != nil {
		t.Fatal(err)
	}
	protocol := New(store)
	for _, device := range []omci.DeviceIdent{omci.BaselineIdent, omci.ExtendedIdent} {
		t.Run(device.String(), func(t *testing.T) {
			upload := encodeRequestForDevice(t, 0x100, omci.MibUploadRequestType,
				&omci.MibUploadRequest{MeBasePacket: omci.MeBasePacket{
					EntityClass: me.OnuDataClassID, Extended: device == omci.ExtendedIdent,
				}}, device)
			encoded, err := protocol.Handle(upload)
			if err != nil {
				t.Fatalf("Handle(MIB upload) error = %v", err)
			}
			response := decodeResponse(t, encoded).Layer(omci.LayerTypeMibUploadResponse).(*omci.MibUploadResponse)
			if response.NumberOfCommands == 0 {
				t.Fatal("complete Factory MIB upload has no commands")
			}
			for sequence := uint16(0); sequence < response.NumberOfCommands; sequence++ {
				next := encodeRequestForDevice(t, sequence+0x101, omci.MibUploadNextRequestType,
					&omci.MibUploadNextRequest{MeBasePacket: omci.MeBasePacket{
						EntityClass: me.OnuDataClassID, Extended: device == omci.ExtendedIdent,
					}, CommandSequenceNumber: sequence}, device)
				frame, err := protocol.Handle(next)
				if err != nil {
					t.Fatalf("Handle(MIB upload next %d/%d) error = %v",
						sequence, response.NumberOfCommands, err)
				}
				decodeResponse(t, frame)
			}
		})
	}
}

func TestMibUploadNextInvalidSequenceReturnsEmptyResponse(t *testing.T) {
	for name, device := range map[string]omci.DeviceIdent{
		"baseline": omci.BaselineIdent,
		"extended": omci.ExtendedIdent,
	} {
		t.Run(name, func(t *testing.T) {
			protocol, _ := newTestEngine(t)
			upload := encodeRequestForDevice(t, 0x120, omci.MibUploadRequestType,
				&omci.MibUploadRequest{MeBasePacket: omci.MeBasePacket{
					EntityClass: me.OnuDataClassID,
					Extended:    device == omci.ExtendedIdent,
				}}, device)
			if _, err := protocol.Handle(upload); err != nil {
				t.Fatalf("Handle(MIB upload) error = %v", err)
			}

			next := encodeRequestForDevice(t, 0x121, omci.MibUploadNextRequestType,
				&omci.MibUploadNextRequest{
					MeBasePacket: omci.MeBasePacket{
						EntityClass: me.OnuDataClassID,
						Extended:    device == omci.ExtendedIdent,
					},
					CommandSequenceNumber: 1,
				}, device)
			encoded, err := protocol.Handle(next)
			if err != nil {
				t.Fatalf("Handle(out-of-range MIB upload next) error = %v", err)
			}
			assertEmptyMibUploadNext(t, encoded, device)
		})
	}
}

func TestMibUploadSessionExpiresAndValidNextRefreshesIt(t *testing.T) {
	t.Run("expires at one minute", func(t *testing.T) {
		protocol, _ := newTestEngine(t)
		now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
		protocol.now = func() time.Time { return now }
		upload := encodeRequest(t, 0x130, omci.MibUploadRequestType,
			&omci.MibUploadRequest{MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID}})
		if _, err := protocol.Handle(upload); err != nil {
			t.Fatalf("Handle(MIB upload) error = %v", err)
		}
		now = now.Add(mibUploadTimeout)
		next := encodeRequest(t, 0x131, omci.MibUploadNextRequestType,
			&omci.MibUploadNextRequest{
				MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID},
				CommandSequenceNumber: 0,
			})
		encoded, err := protocol.Handle(next)
		if err != nil {
			t.Fatalf("Handle(expired MIB upload next) error = %v", err)
		}
		assertEmptyMibUploadNext(t, encoded, omci.BaselineIdent)
	})

	t.Run("valid request and retransmission refresh", func(t *testing.T) {
		protocol, _ := newTestEngine(t)
		now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
		protocol.now = func() time.Time { return now }
		upload := encodeRequest(t, 0x140, omci.MibUploadRequestType,
			&omci.MibUploadRequest{MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID}})
		if _, err := protocol.Handle(upload); err != nil {
			t.Fatalf("Handle(MIB upload) error = %v", err)
		}

		now = now.Add(59 * time.Second)
		next := encodeRequest(t, 0x141, omci.MibUploadNextRequestType,
			&omci.MibUploadNextRequest{
				MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID},
				CommandSequenceNumber: 0,
			})
		first, err := protocol.Handle(next)
		if err != nil || !mibUploadNextHasContents(first, omci.BaselineIdent) {
			t.Fatalf("first MIB upload next: contents=%t error=%v",
				mibUploadNextHasContents(first, omci.BaselineIdent), err)
		}

		now = now.Add(59 * time.Second)
		replayed, err := protocol.Handle(next)
		if err != nil || string(replayed) != string(first) {
			t.Fatalf("retransmitted MIB upload next was not replayed: error=%v", err)
		}

		now = now.Add(59 * time.Second)
		later := encodeRequest(t, 0x142, omci.MibUploadNextRequestType,
			&omci.MibUploadNextRequest{
				MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID},
				CommandSequenceNumber: 0,
			})
		encoded, err := protocol.Handle(later)
		if err != nil || !mibUploadNextHasContents(encoded, omci.BaselineIdent) {
			t.Fatalf("refreshed MIB upload next: contents=%t error=%v",
				mibUploadNextHasContents(encoded, omci.BaselineIdent), err)
		}
	})
}

func TestMibUploadExcludesPerformanceCounters(t *testing.T) {
	snapshot := []mib.Instance{{
		Key: mib.Key{ClassID: me.EthernetPerformanceMonitoringHistoryData2ClassID, EntityID: 1},
		Attributes: me.AttributeValueMap{
			me.EthernetPerformanceMonitoringHistoryData2_IntervalEndTime:           uint8(7),
			me.EthernetPerformanceMonitoringHistoryData2_ThresholdData12Id:         uint16(2),
			me.EthernetPerformanceMonitoringHistoryData2_PppoeFilteredFrameCounter: uint32(99),
		},
	}}
	commands, err := buildUpload(snapshot, omci.BaselineIdent)
	if err != nil {
		t.Fatalf("buildUpload() error = %v", err)
	}
	if len(commands) != 1 || len(commands[0]) != 1 {
		t.Fatalf("upload commands = %#v, want one ME", commands)
	}
	reported := commands[0][0]
	if got := reported.GetAttributeMask(); got != 0x4000 {
		t.Fatalf("reported attribute mask = %#x, want control block 0x4000", got)
	}
	if _, present := reported.GetAttributeValueMap()[me.EthernetPerformanceMonitoringHistoryData2_IntervalEndTime]; present {
		t.Fatal("MIB upload includes transient PM interval end time")
	}
	if _, present := reported.GetAttributeValueMap()[me.EthernetPerformanceMonitoringHistoryData2_PppoeFilteredFrameCounter]; present {
		t.Fatal("MIB upload includes a PM measurement counter")
	}
}

func TestMibUploadIncludesExtendedPMControlBlockOnly(t *testing.T) {
	controlBlock := make([]byte, 16)
	controlBlock[0] = 1
	snapshot := []mib.Instance{{
		Key: mib.Key{ClassID: me.EthernetFrameExtendedPmClassID, EntityID: 1},
		Attributes: me.AttributeValueMap{
			me.EthernetFrameExtendedPm_IntervalEndTime: uint8(7),
			me.EthernetFrameExtendedPm_ControlBlock:    controlBlock,
			me.EthernetFrameExtendedPm_DropEvents:      uint32(99),
		},
	}}
	commands, err := buildUpload(snapshot, omci.ExtendedIdent)
	if err != nil {
		t.Fatalf("buildUpload() error = %v", err)
	}
	if len(commands) != 1 || len(commands[0]) != 1 {
		t.Fatalf("upload commands = %#v, want one ME", commands)
	}
	reported := commands[0][0]
	if got := reported.GetAttributeMask(); got != 0x4000 {
		t.Fatalf("reported attribute mask = %#x, want control block 0x4000", got)
	}
	attributes := reported.GetAttributeValueMap()
	if got, present := attributes[me.EthernetFrameExtendedPm_ControlBlock]; !present || string(got.([]byte)) != string(controlBlock) {
		t.Fatalf("reported control block = %#v, want %#v", got, controlBlock)
	}
	if _, present := attributes[me.EthernetFrameExtendedPm_IntervalEndTime]; present {
		t.Fatal("MIB upload includes transient extended PM interval end time")
	}
	if _, present := attributes[me.EthernetFrameExtendedPm_DropEvents]; present {
		t.Fatal("MIB upload includes an extended PM measurement counter")
	}
}

func TestMibUploadExcludesManagedEntitiesProhibitedByG988(t *testing.T) {
	snapshot := []mib.Instance{
		{
			Key: mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(0),
			},
		},
		{Key: mib.Key{ClassID: me.PhysicalPathTerminationPointLctUniClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{
				me.PhysicalPathTerminationPointLctUni_AdministrativeState: uint8(0),
			}},
		{Key: mib.Key{ClassID: me.SipConfigPortalClassID, EntityID: 0}},
		{Key: mib.Key{ClassID: me.MgcConfigPortalClassID, EntityID: 0}},
		{Key: mib.Key{ClassID: me.OmciClassID, EntityID: 0}},
		{Key: mib.Key{ClassID: me.ManagedEntityMeClassID, EntityID: uint16(me.OnuDataClassID)}},
		{Key: mib.Key{ClassID: me.AttributeMeClassID, EntityID: 1}},
		{Key: mib.Key{ClassID: me.GeneralPurposeBufferClassID, EntityID: 1},
			Attributes: me.AttributeValueMap{
				me.GeneralPurposeBuffer_MaximumSize: uint32(4096),
			}},
	}
	for _, device := range []omci.DeviceIdent{omci.BaselineIdent, omci.ExtendedIdent} {
		commands, err := buildUpload(snapshot, device)
		if err != nil {
			t.Fatalf("buildUpload(%#x) error = %v", byte(device), err)
		}
		if len(commands) != 1 || len(commands[0]) != 1 ||
			commands[0][0].GetClassID() != me.OnuDataClassID {
			t.Fatalf("MIB upload %#x commands = %#v, want only ONU data", byte(device), commands)
		}
	}
}

func TestGetONUData(t *testing.T) {
	engine, _ := newTestEngine(t)
	request := encodeRequest(t, 5, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AttributeMask: 0x8000,
	})
	encoded, err := engine.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.Success {
		t.Fatalf("Get result = %v, want success", response.Result)
	}
	if got := response.Attributes[me.OnuData_MibDataSync]; got != uint8(0) {
		t.Fatalf("MIB data sync = %#v, want 0", got)
	}
}

func TestSetMibDataSyncUsesOLTValueAndRetransmissionDoesNotIncrementAgain(t *testing.T) {
	protocol, store := newTestEngine(t)
	request := encodeRequest(t, 0x150, omci.SetRequestType, &omci.SetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AttributeMask: 0x8000,
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(7),
		},
	})
	first, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Set MIB data sync) error = %v", err)
	}
	response := decodeResponse(t, first).Layer(omci.LayerTypeSetResponse).(*omci.SetResponse)
	if response.Result != me.Success || store.DataSync() != 8 {
		t.Fatalf("Set result=%v data sync=%d, want Success/8", response.Result, store.DataSync())
	}

	replayed, err := protocol.Handle(request)
	if err != nil || string(replayed) != string(first) || store.DataSync() != 8 {
		t.Fatalf("retransmitted Set changed state: same=%t sync=%d error=%v",
			string(replayed) == string(first), store.DataSync(), err)
	}
}

func TestGetReturnsSupportedAttributesAlongsideFailureMask(t *testing.T) {
	engine, _ := newTestEngine(t)
	request := encodeRequest(t, 6, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AttributeMask: 0xc000,
	})
	encoded, err := engine.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Get) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if response.Result != me.AttributeFailure || response.UnsupportedAttributeMask != 0x4000 {
		t.Fatalf("Get result = %v unsupported=%#x, want AttributeFailure/0x4000", response.Result, response.UnsupportedAttributeMask)
	}
	if got := response.Attributes[me.OnuData_MibDataSync]; got != uint8(0) {
		t.Fatalf("MIB data sync = %#v, want 0", got)
	}
}

func TestUnknownEntityGetsProtocolErrorResponse(t *testing.T) {
	engine, _ := newTestEngine(t)
	request := encodeRequest(t, 7, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket:  omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AttributeMask: 0x8000,
	})
	binary.BigEndian.PutUint16(request[4:6], 0xfffe)

	encoded, err := engine.Handle(request)
	if err != nil {
		t.Fatalf("Handle(unknown class) error = %v", err)
	}
	if got := omci.MessageType(encoded[2]); got != omci.GetResponseType {
		t.Fatalf("message type = %v, want Get response", got)
	}
	if got := me.Results(encoded[8]); got != me.UnknownEntity {
		t.Fatalf("result = %v, want UnknownEntity", got)
	}
}

func TestPlatformFailureReturnsProcessingErrorWithoutMutation(t *testing.T) {
	store, err := mib.NewWithApplier([]mib.Instance{{
		Key: mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}}, mib.ApplyFunc(func(mib.Change) error { return errors.New("apply failed") }))
	if err != nil {
		t.Fatalf("NewWithApplier() error = %v", err)
	}
	protocol := New(store)
	request := encodeRequest(t, 8, omci.CreateRequestType, &omci.CreateRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.GalEthernetProfileClassID,
			EntityInstance: 1,
		},
		Attributes: me.AttributeValueMap{
			me.GalEthernetProfile_MaximumGemPayloadSize: uint16(48),
		},
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(Create) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeCreateResponse).(*omci.CreateResponse)
	if response.Result != me.ProcessingError {
		t.Fatalf("Create result = %v, want ProcessingError", response.Result)
	}
	if store.DataSync() != 0 || len(store.Snapshot()) != 1 {
		t.Fatalf("rejected platform apply changed MIB: sync=%d MEs=%d", store.DataSync(), len(store.Snapshot()))
	}
}

func TestGetNextUsesStableTableSnapshot(t *testing.T) {
	rows := make([]byte, 32)
	for index := range rows {
		rows[index] = byte(index + 1)
	}
	store, err := mib.New([]mib.Instance{{
		Key: mib.Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: 1},
		Attributes: me.AttributeValueMap{
			me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:                               uint8(2),
			me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize: uint16(8),
			me.ExtendedVlanTaggingOperationConfigurationData_InputTpid:                                     uint16(0x8100),
			me.ExtendedVlanTaggingOperationConfigurationData_OutputTpid:                                    uint16(0x8100),
			me.ExtendedVlanTaggingOperationConfigurationData_DownstreamMode:                                uint8(0),
			me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable: me.TableRows{
				NumRows: 2,
				Rows:    rows,
			},
		},
	}})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	protocol := New(store)
	get := encodeRequest(t, 9, omci.GetRequestType, &omci.GetRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: 1,
		},
		AttributeMask: 0x0400,
	})
	encoded, err := protocol.Handle(get)
	if err != nil {
		t.Fatalf("Handle(Get table) error = %v", err)
	}
	getResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetResponse).(*omci.GetResponse)
	if got := getResponse.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable]; got != uint32(len(rows)) {
		t.Fatalf("table size = %#v, want %d", got, len(rows))
	}

	next := encodeRequest(t, 10, omci.GetNextRequestType, &omci.GetNextRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    me.ExtendedVlanTaggingOperationConfigurationDataClassID,
			EntityInstance: 1,
		},
		AttributeMask:  0x0400,
		SequenceNumber: 0,
	})
	encoded, err = protocol.Handle(next)
	if err != nil {
		t.Fatalf("Handle(GetNext) error = %v", err)
	}
	nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetNextResponse).(*omci.GetNextResponse)
	got, ok := nextResponse.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable].([]byte)
	if !ok || len(got) < omci.MaxAttributeGetNextBaselineLength ||
		string(got[:omci.MaxAttributeGetNextBaselineLength]) != string(rows[:omci.MaxAttributeGetNextBaselineLength]) {
		t.Fatalf("GetNext table chunk = %x", got)
	}
}

func TestExtendedSetTableCommitsRowsOnceAcrossRetransmission(t *testing.T) {
	key := mib.Key{ClassID: me.ExtendedVlanTaggingOperationConfigurationDataClassID, EntityID: 1}
	store, err := mib.New([]mib.Instance{
		{
			Key:        mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
			Attributes: me.AttributeValueMap{me.OnuData_MibDataSync: uint8(0)},
		},
		{
			Key: key,
			Attributes: me.AttributeValueMap{
				me.ExtendedVlanTaggingOperationConfigurationData_AssociationType:                               uint8(2),
				me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTableMaxSize: uint16(8),
				me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable:        me.TableRows{},
				me.ExtendedVlanTaggingOperationConfigurationData_AssociatedMePointer:                           uint16(0x101),
			},
		},
	})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	protocol := New(store)
	row := make([]byte, 16)
	row[7] = 1
	row[15] = 2
	request := encodeRequestForDevice(t, 11, omci.SetTableRequestType, &omci.SetTableRequest{
		MeBasePacket: omci.MeBasePacket{
			EntityClass:    key.ClassID,
			EntityInstance: key.EntityID,
			Extended:       true,
		},
		AttributeMask: 0x0400,
		Attributes: me.AttributeValueMap{
			me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable: me.TableRows{
				NumRows: 1,
				Rows:    row,
			},
		},
	}, omci.ExtendedIdent)

	first, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(first SetTable) error = %v", err)
	}
	second, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(retransmitted SetTable) error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("retransmitted SetTable response differs from original")
	}
	response := decodeResponse(t, first).Layer(omci.LayerTypeSetTableResponse).(*omci.SetTableResponse)
	if response.Result != me.Success {
		t.Fatalf("SetTable result = %v, want Success", response.Result)
	}
	if store.DataSync() != 1 {
		t.Fatalf("DataSync() = %d, want one mutation", store.DataSync())
	}
	instance, err := store.Get(key, 0x0400)
	if err != nil {
		t.Fatalf("Get(table) error = %v", err)
	}
	rows := instance.Attributes[me.ExtendedVlanTaggingOperationConfigurationData_ReceivedFrameVlanTaggingOperationTable].(me.TableRows)
	if rows.NumRows != 1 || string(rows.Rows) != string(row) {
		t.Fatalf("stored rows = %#v, want one transmitted row", rows)
	}
}

func TestExtendedMibUploadPacksMultipleManagedEntities(t *testing.T) {
	snapshot := make([]mib.Instance, 300)
	for index := range snapshot {
		snapshot[index] = mib.Instance{
			Key: mib.Key{ClassID: me.OnuDataClassID, EntityID: uint16(index)},
			Attributes: me.AttributeValueMap{
				me.OnuData_MibDataSync: uint8(index),
			},
		}
	}
	commands, err := buildUpload(snapshot, omci.ExtendedIdent)
	if err != nil {
		t.Fatalf("buildUpload() error = %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("extended upload commands = %d, want 2", len(commands))
	}
	reported := 0
	for sequence, command := range commands {
		reported += len(command)
		encoded, err := serialize(&omci.OMCI{
			TransactionID:    uint16(sequence + 1),
			MessageType:      omci.MibUploadNextRequestType,
			DeviceIdentifier: omci.ExtendedIdent,
		}, omci.MibUploadNextResponseType, &omci.MibUploadNextResponse{
			MeBasePacket: omci.MeBasePacket{
				EntityClass: me.OnuDataClassID,
				Extended:    true,
			},
			ReportedME:    command[0],
			AdditionalMEs: command[1:],
		})
		if err != nil {
			t.Fatalf("serialize(command %d) error = %v", sequence, err)
		}
		if len(encoded) > omci.MaxExtendedLength {
			t.Fatalf("serialized command %d length = %d, maximum %d",
				sequence, len(encoded), omci.MaxExtendedLength)
		}
	}
	if reported != len(snapshot) {
		t.Fatalf("reported MEs = %d, want %d", reported, len(snapshot))
	}
}

func TestGetAllAlarmsUsesStableSnapshot(t *testing.T) {
	protocol, _ := newTestEngine(t)
	var bitmap [28]byte
	bitmap[0] = 0x80
	protocol.SetAlarm(mib.Key{ClassID: me.AniGClassID, EntityID: 0x8001}, bitmap)

	request := encodeRequest(t, 11, omci.GetAllAlarmsRequestType, &omci.GetAllAlarmsRequest{
		MeBasePacket:       omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AlarmRetrievalMode: 0,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(GetAllAlarms) error = %v", err)
	}
	response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetAllAlarmsResponse).(*omci.GetAllAlarmsResponse)
	if response.NumberOfCommands != 1 {
		t.Fatalf("NumberOfCommands = %d, want 1", response.NumberOfCommands)
	}
	protocol.SetAlarm(mib.Key{ClassID: me.AniGClassID, EntityID: 0x8001}, [28]byte{})

	next := encodeRequest(t, 12, omci.GetAllAlarmsNextRequestType, &omci.GetAllAlarmsNextRequest{
		MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		CommandSequenceNumber: 0,
	})
	encoded, err = protocol.Handle(next)
	if err != nil {
		t.Fatalf("Handle(GetAllAlarmsNext) error = %v", err)
	}
	nextResponse := decodeResponse(t, encoded).Layer(omci.LayerTypeGetAllAlarmsNextResponse).(*omci.GetAllAlarmsNextResponse)
	if nextResponse.AlarmEntityClass != me.AniGClassID ||
		nextResponse.AlarmEntityInstance != 0x8001 || nextResponse.AlarmBitMap != bitmap {
		t.Fatalf("alarm response = %#v", nextResponse)
	}
}

func TestGetAllAlarmsRejectsReservedRetrievalMode(t *testing.T) {
	protocol, _ := newTestEngine(t)
	request := encodeRequest(t, 0x180, omci.GetAllAlarmsRequestType, &omci.GetAllAlarmsRequest{
		MeBasePacket:       omci.MeBasePacket{EntityClass: me.OnuDataClassID},
		AlarmRetrievalMode: 2,
	})
	if _, err := protocol.Handle(request); err == nil {
		t.Fatal("Handle(GetAllAlarms mode 2) error = nil, want malformed request rejection")
	}
}

func TestGetAllAlarmsSessionExpiresAndValidNextRefreshesIt(t *testing.T) {
	newProtocol := func(t *testing.T) (*Engine, *time.Time) {
		t.Helper()
		protocol, _ := newTestEngine(t)
		now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
		protocol.now = func() time.Time { return now }
		var bitmap [28]byte
		bitmap[0] = 0x80
		protocol.SetAlarm(mib.Key{ClassID: me.AniGClassID, EntityID: 0x8001}, bitmap)
		return protocol, &now
	}

	t.Run("expires at one minute", func(t *testing.T) {
		for name, device := range map[string]omci.DeviceIdent{
			"baseline": omci.BaselineIdent,
			"extended": omci.ExtendedIdent,
		} {
			t.Run(name, func(t *testing.T) {
				protocol, now := newProtocol(t)
				extended := device == omci.ExtendedIdent
				start := encodeRequestForDevice(t, 0x181, omci.GetAllAlarmsRequestType,
					&omci.GetAllAlarmsRequest{MeBasePacket: omci.MeBasePacket{
						EntityClass: me.OnuDataClassID, Extended: extended,
					}}, device)
				if _, err := protocol.Handle(start); err != nil {
					t.Fatalf("Handle(GetAllAlarms) error = %v", err)
				}
				*now = now.Add(alarmUploadTimeout)
				next := encodeRequestForDevice(t, 0x182, omci.GetAllAlarmsNextRequestType,
					&omci.GetAllAlarmsNextRequest{
						MeBasePacket: omci.MeBasePacket{
							EntityClass: me.OnuDataClassID, Extended: extended,
						},
					}, device)
				encoded, err := protocol.Handle(next)
				if err != nil {
					t.Fatalf("Handle(expired GetAllAlarmsNext) error = %v", err)
				}
				if getAllAlarmsNextHasContents(encoded, device) {
					t.Fatalf("expired GetAllAlarmsNext %#x returned contents", byte(device))
				}
			})
		}
	})

	t.Run("valid request and retransmission refresh", func(t *testing.T) {
		protocol, now := newProtocol(t)
		start := encodeRequest(t, 0x183, omci.GetAllAlarmsRequestType,
			&omci.GetAllAlarmsRequest{MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID}})
		if _, err := protocol.Handle(start); err != nil {
			t.Fatalf("Handle(GetAllAlarms) error = %v", err)
		}

		*now = now.Add(59 * time.Second)
		next := encodeRequest(t, 0x184, omci.GetAllAlarmsNextRequestType,
			&omci.GetAllAlarmsNextRequest{MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID}})
		first, err := protocol.Handle(next)
		if err != nil || !getAllAlarmsNextHasContents(first, omci.BaselineIdent) {
			t.Fatalf("first GetAllAlarmsNext: contents=%t error=%v",
				getAllAlarmsNextHasContents(first, omci.BaselineIdent), err)
		}

		*now = now.Add(59 * time.Second)
		replayed, err := protocol.Handle(next)
		if err != nil || string(replayed) != string(first) {
			t.Fatalf("retransmitted GetAllAlarmsNext was not replayed: error=%v", err)
		}

		*now = now.Add(59 * time.Second)
		later := encodeRequest(t, 0x185, omci.GetAllAlarmsNextRequestType,
			&omci.GetAllAlarmsNextRequest{MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuDataClassID}})
		encoded, err := protocol.Handle(later)
		if err != nil || !getAllAlarmsNextHasContents(encoded, omci.BaselineIdent) {
			t.Fatalf("refreshed GetAllAlarmsNext: contents=%t error=%v",
				getAllAlarmsNextHasContents(encoded, omci.BaselineIdent), err)
		}
	})
}

func TestExtendedGetAllAlarmsPacksSnapshotFromRequestedIndex(t *testing.T) {
	protocol, _ := newTestEngine(t)
	var bitmap [28]byte
	bitmap[0] = 0x80
	for entityID := uint16(1); entityID <= 100; entityID++ {
		protocol.SetAlarm(mib.Key{ClassID: me.AniGClassID, EntityID: entityID}, bitmap)
	}
	start := encodeRequestForDevice(t, 0x190, omci.GetAllAlarmsRequestType,
		&omci.GetAllAlarmsRequest{MeBasePacket: omci.MeBasePacket{
			EntityClass: me.OnuDataClassID, Extended: true,
		}}, omci.ExtendedIdent)
	encoded, err := protocol.Handle(start)
	if err != nil {
		t.Fatalf("Handle(GetAllAlarms) error = %v", err)
	}
	audit := decodeResponse(t, encoded).Layer(omci.LayerTypeGetAllAlarmsResponse).(*omci.GetAllAlarmsResponse)
	if audit.NumberOfCommands != 100 {
		t.Fatalf("extended alarm instance count = %d, want 100", audit.NumberOfCommands)
	}

	for _, test := range []struct {
		sequence uint16
		want     int
	}{
		{sequence: 0, want: maxExtendedAlarmsPerResponse},
		{sequence: maxExtendedAlarmsPerResponse, want: 100 - maxExtendedAlarmsPerResponse},
	} {
		next := encodeRequestForDevice(t, 0x191+test.sequence, omci.GetAllAlarmsNextRequestType,
			&omci.GetAllAlarmsNextRequest{
				MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID, Extended: true},
				CommandSequenceNumber: test.sequence,
			}, omci.ExtendedIdent)
		encoded, err = protocol.Handle(next)
		if err != nil {
			t.Fatalf("Handle(GetAllAlarmsNext %d) error = %v", test.sequence, err)
		}
		response := decodeResponse(t, encoded).Layer(omci.LayerTypeGetAllAlarmsNextResponse).(*omci.GetAllAlarmsNextResponse)
		if got := 1 + len(response.AdditionalAlarms); got != test.want {
			t.Fatalf("GetAllAlarmsNext %d entries = %d, want %d", test.sequence, got, test.want)
		}
		if response.AlarmEntityInstance != test.sequence+1 {
			t.Fatalf("GetAllAlarmsNext %d first entity = %d, want %d",
				test.sequence, response.AlarmEntityInstance, test.sequence+1)
		}
	}

	outOfRange := encodeRequestForDevice(t, 0x1ff, omci.GetAllAlarmsNextRequestType,
		&omci.GetAllAlarmsNextRequest{
			MeBasePacket:          omci.MeBasePacket{EntityClass: me.OnuDataClassID, Extended: true},
			CommandSequenceNumber: 100,
		}, omci.ExtendedIdent)
	encoded, err = protocol.Handle(outOfRange)
	if err != nil {
		t.Fatalf("Handle(out-of-range GetAllAlarmsNext) error = %v", err)
	}
	if getAllAlarmsNextHasContents(encoded, omci.ExtendedIdent) {
		t.Fatal("out-of-range extended GetAllAlarmsNext returned contents")
	}
}

type recordingController struct {
	timestamp   time.Time
	reboot      uint8
	diagnostics optical.Diagnostics
	opticalErr  error
	opticalRuns int
}

func (c *recordingController) SynchronizeTime(value time.Time) error {
	c.timestamp = value
	return nil
}

func (c *recordingController) Reboot(condition uint8) error {
	c.reboot = condition
	return nil
}

func (c *recordingController) OpticalLineSupervision() (optical.Diagnostics, error) {
	c.opticalRuns++
	return c.diagnostics, c.opticalErr
}

func TestOpticalLineSupervisionRespondsThenReportsResults(t *testing.T) {
	store, err := mib.New([]mib.Instance{{
		Key:        mib.Key{ClassID: me.AniGClassID, EntityID: 0x8001},
		Attributes: me.AttributeValueMap{},
	}})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	for _, device := range []omci.DeviceIdent{omci.BaselineIdent, omci.ExtendedIdent} {
		t.Run(device.String(), func(t *testing.T) {
			controller := &recordingController{diagnostics: optical.Diagnostics{
				PowerFeedVoltage: 165, ReceivedOpticalPower: 0xff00,
				MeanOpticalLaunch: 15000, LaserBiasCurrent: 2500,
				Temperature: 0xf600,
			}}
			protocol := NewWithController(store, controller)
			var request []byte
			if device == omci.ExtendedIdent {
				request = make([]byte, 15)
				binary.BigEndian.PutUint16(request, 0x1234)
				request[2] = byte(omci.TestRequestType)
				request[3] = byte(omci.ExtendedIdent)
				binary.BigEndian.PutUint16(request[4:], uint16(me.AniGClassID))
				binary.BigEndian.PutUint16(request[6:], 0x8001)
				binary.BigEndian.PutUint16(request[8:], 5)
				request[10] = 7
			} else {
				request = encodeRequest(t, 0x1234, omci.TestRequestType,
					&omci.OpticalLineSupervisionTestRequest{
						MeBasePacket: omci.MeBasePacket{
							EntityClass: me.AniGClassID, EntityInstance: 0x8001,
						},
						SelectTest: 7,
					})
			}
			responseFrame, err := protocol.Handle(request)
			if err != nil {
				t.Fatalf("Handle(Test) error = %v", err)
			}
			if device == omci.ExtendedIdent {
				if len(responseFrame) != 11 || binary.BigEndian.Uint16(responseFrame[8:10]) != 1 ||
					me.Results(responseFrame[10]) != me.Success {
					t.Fatalf("extended Test response = %x", responseFrame)
				}
			} else {
				response := decodeResponse(t, responseFrame).Layer(omci.LayerTypeTestResponse).(*omci.TestResponse)
				if response.Result != me.Success {
					t.Fatalf("Test result = %v, want Success", response.Result)
				}
			}
			pending := protocol.DrainNotifications()
			if len(pending) != 1 {
				t.Fatalf("pending notifications = %d, want 1", len(pending))
			}
			packet := decodeResponse(t, pending[0])
			header := packet.Layer(omci.LayerTypeOMCI).(*omci.OMCI)
			result := packet.Layer(omci.LayerTypeTestResult).(*omci.OpticalLineSupervisionTestResult)
			if header.TransactionID != 0x1234 || header.DeviceIdentifier != device ||
				result.PowerFeedVoltageType != 1 || result.PowerFeedVoltage != 165 ||
				result.ReceivedOpticalPowerType != 3 || result.ReceivedOpticalPower != 0xff00 ||
				result.MeanOpticalLaunchType != 5 || result.MeanOpticalLaunch != 15000 ||
				result.LaserBiasCurrentType != 9 || result.LaserBiasCurrent != 2500 ||
				result.TemperatureType != 12 || result.Temperature != 0xf600 {
				t.Fatalf("optical test result = %#v, header = %#v", result, header)
			}

			if _, err := protocol.Handle(request); err != nil {
				t.Fatalf("Handle(duplicate Test) error = %v", err)
			}
			if controller.opticalRuns != 1 || len(protocol.DrainNotifications()) != 0 {
				t.Fatalf("duplicate reran optical test: runs=%d", controller.opticalRuns)
			}
		})
	}
}

func TestSynchronizeTimeHandlesBaselineLibraryDecodeFailure(t *testing.T) {
	_, store := newTestEngine(t)
	controller := &recordingController{}
	protocol := NewWithController(store, controller)
	request := encodeRequest(t, 13, omci.SynchronizeTimeRequestType, &omci.SynchronizeTimeRequest{
		MeBasePacket: omci.MeBasePacket{EntityClass: me.OnuGClassID},
		Year:         2026,
		Month:        8,
		Day:          10,
		Hour:         12,
		Minute:       34,
		Second:       56,
	})
	encoded, err := protocol.Handle(request)
	if err != nil {
		t.Fatalf("Handle(SynchronizeTime) error = %v", err)
	}
	if got := me.Results(encoded[8]); got != me.Success {
		t.Fatalf("result = %v, want Success", got)
	}
	want := time.Date(2026, 8, 10, 12, 34, 56, 0, time.UTC)
	if !controller.timestamp.Equal(want) {
		t.Fatalf("timestamp = %v, want %v", controller.timestamp, want)
	}
}

func TestRebootValidatesTargetAndReservedCondition(t *testing.T) {
	store, err := mib.New([]mib.Instance{{
		Key: mib.Key{ClassID: me.OnuGClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuG_VendorId: []byte("TEST"), me.OnuG_Version: make([]byte, 14),
			me.OnuG_SerialNumber: make([]byte, 8),
		},
	}})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	controller := &recordingController{reboot: 0xff}
	protocol := NewWithController(store, controller)

	request := func(tci uint16, entityID uint16, condition uint8) []byte {
		return encodeRequest(t, tci, omci.RebootRequestType, &omci.RebootRequest{
			MeBasePacket: omci.MeBasePacket{
				EntityClass: me.OnuGClassID, EntityInstance: entityID,
			},
			RebootCondition: condition,
		})
	}
	for _, test := range []struct {
		name      string
		request   []byte
		want      me.Results
		wantCalls bool
	}{
		{name: "wrong instance", request: request(0x701, 1, 0), want: me.UnknownInstance},
		{name: "reserved condition", request: request(0x702, 0, 3), want: me.ParameterError},
		{name: "valid conditional", request: request(0x703, 0, 2), want: me.Success, wantCalls: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller.reboot = 0xff
			encoded, err := protocol.Handle(test.request)
			if err != nil {
				t.Fatalf("Handle(Reboot) error = %v", err)
			}
			response := decodeResponse(t, encoded).Layer(omci.LayerTypeRebootResponse).(*omci.RebootResponse)
			if response.Result != test.want {
				t.Fatalf("Reboot result = %v, want %v", response.Result, test.want)
			}
			called := controller.reboot != 0xff
			if called != test.wantCalls {
				t.Fatalf("controller called = %v, want %v", called, test.wantCalls)
			}
		})
	}
}

func newTestEngine(t *testing.T) (*Engine, *mib.Store) {
	t.Helper()
	store, err := mib.New([]mib.Instance{{
		Key: mib.Key{ClassID: me.OnuDataClassID, EntityID: 0},
		Attributes: me.AttributeValueMap{
			me.OnuData_MibDataSync: uint8(0),
		},
	}})
	if err != nil {
		t.Fatalf("mib.New() error = %v", err)
	}
	return New(store), store
}

func encodeRequest(t *testing.T, transactionID uint16, messageType omci.MessageType, payload gopacket.SerializableLayer) []byte {
	return encodeRequestForDevice(t, transactionID, messageType, payload, omci.BaselineIdent)
}

func encodeRequestForDevice(t *testing.T, transactionID uint16, messageType omci.MessageType,
	payload gopacket.SerializableLayer, device omci.DeviceIdent) []byte {
	t.Helper()
	header := &omci.OMCI{
		TransactionID:    transactionID,
		MessageType:      messageType,
		DeviceIdentifier: device,
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, header, payload); err != nil {
		t.Fatalf("SerializeLayers() error = %v", err)
	}
	return buffer.Bytes()
}

func decodeResponse(t *testing.T, encoded []byte) gopacket.Packet {
	t.Helper()
	packet := gopacket.NewPacket(encoded, omci.LayerTypeOMCI, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil {
		t.Fatalf("decode response error = %v\nframe = %x", err.Error(), encoded)
	}
	return packet
}

func assertEmptyMibUploadNext(t *testing.T, encoded []byte, device omci.DeviceIdent) {
	t.Helper()
	if len(encoded) < 10 || encoded[2] != byte(omci.MibUploadNextResponseType) ||
		encoded[3] != byte(device) || binary.BigEndian.Uint16(encoded[4:6]) != uint16(me.OnuDataClassID) ||
		binary.BigEndian.Uint16(encoded[6:8]) != 0 {
		t.Fatalf("invalid empty MIB upload next response: %x", encoded)
	}
	if device == omci.ExtendedIdent {
		if len(encoded) != 10 || binary.BigEndian.Uint16(encoded[8:10]) != 0 {
			t.Fatalf("extended empty MIB upload next response = %x", encoded)
		}
		return
	}
	if len(encoded) != omci.MaxBaselineLength-4 {
		t.Fatalf("baseline empty response length = %d, want %d", len(encoded), omci.MaxBaselineLength-4)
	}
	for offset, value := range encoded[8:40] {
		if value != 0 {
			t.Fatalf("baseline empty response byte %d = %#x, want 0", offset+9, value)
		}
	}
}
