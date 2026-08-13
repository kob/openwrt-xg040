// SPDX-License-Identifier: Apache-2.0

// Package performance defines the platform-independent counter values used by
// G.988 performance monitoring managed entities.
package performance

type GEMPortCounters struct {
	ReceivedGEMFrames       uint64 `json:"received_gem_frames"`
	ReceivedPayloadBytes    uint64 `json:"received_payload_bytes"`
	TransmittedGEMFrames    uint64 `json:"transmitted_gem_frames"`
	TransmittedPayloadBytes uint64 `json:"transmitted_payload_bytes"`
}

type FECCounters struct {
	CorrectedBytes         uint64 `json:"corrected_bytes"`
	CorrectedCodeWords     uint64 `json:"corrected_codewords"`
	UncorrectableCodeWords uint64 `json:"uncorrectable_codewords"`
	TotalCodeWords         uint64 `json:"total_codewords"`
	FECSeconds             uint64 `json:"fec_seconds"`
}

type XGSPONTCCounters struct {
	PSBdHECErrors           uint64 `json:"psbd_hec_errors"`
	XGTCHECErrors           uint64 `json:"xgtc_hec_errors"`
	UnknownProfiles         uint64 `json:"unknown_profiles"`
	TransmittedXGEMFrames   uint64 `json:"transmitted_xgem_frames"`
	FragmentXGEMFrames      uint64 `json:"fragment_xgem_frames"`
	XGEMHECLostWords        uint64 `json:"xgem_hec_lost_words"`
	XGEMKeyErrors           uint64 `json:"xgem_key_errors"`
	XGEMHECErrors           uint64 `json:"xgem_hec_errors"`
	TransmittedNonIdleBytes uint64 `json:"transmitted_non_idle_bytes"`
	ReceivedNonIdleBytes    uint64 `json:"received_non_idle_bytes"`
	LODSEvents              uint64 `json:"lods_events"`
	LODSRestored            uint64 `json:"lods_restored"`
	ONUReactivationsByLODS  uint64 `json:"onu_reactivations_by_lods"`
}

type XGSPONDownstreamManagementCounters struct {
	PLOAMMICErrors              uint64 `json:"ploam_mic_errors"`
	PLOAMMessages               uint64 `json:"ploam_messages"`
	ProfileMessages             uint64 `json:"profile_messages"`
	RangingTimeMessages         uint64 `json:"ranging_time_messages"`
	DeactivateONUIDMessages     uint64 `json:"deactivate_onu_id_messages"`
	DisableSerialNumberMessages uint64 `json:"disable_serial_number_messages"`
	RequestRegistrationMessages uint64 `json:"request_registration_messages"`
	AssignAllocIDMessages       uint64 `json:"assign_alloc_id_messages"`
	KeyControlMessages          uint64 `json:"key_control_messages"`
	SleepAllowMessages          uint64 `json:"sleep_allow_messages"`
	BaselineOMCIMessages        uint64 `json:"baseline_omci_messages"`
	ExtendedOMCIMessages        uint64 `json:"extended_omci_messages"`
	AssignONUIDMessages         uint64 `json:"assign_onu_id_messages"`
	OMCIMICErrors               uint64 `json:"omci_mic_errors"`
}

type XGSPONUpstreamManagementCounters struct {
	PLOAMMessages        uint64 `json:"ploam_messages"`
	SerialNumberMessages uint64 `json:"serial_number_messages"`
	RegistrationMessages uint64 `json:"registration_messages"`
	KeyReportMessages    uint64 `json:"key_report_messages"`
	AcknowledgeMessages  uint64 `json:"acknowledge_messages"`
	SleepRequestMessages uint64 `json:"sleep_request_messages"`
}

type XGSPONCounters struct {
	TC         XGSPONTCCounters                   `json:"tc"`
	Downstream XGSPONDownstreamManagementCounters `json:"downstream_management"`
	Upstream   XGSPONUpstreamManagementCounters   `json:"upstream_management"`
}

type EthernetDirectionCounters struct {
	Frames          uint64
	Octets          uint64
	DropEvents      uint64
	BroadcastFrames uint64
	MulticastFrames uint64
	CRCErrors       uint64
	BufferOverflows uint64
	InternalErrors  uint64
	UndersizeFrames uint64
	Fragments       uint64
	Jabbers         uint64
	OversizeFrames  uint64
	SizeBuckets     [6]uint64
}

type EthernetCounters struct {
	Received    EthernetDirectionCounters
	Transmitted EthernetDirectionCounters
}

type Controller interface {
	GEMPortCounters(portID uint16) (GEMPortCounters, error)
}

type EthernetController interface {
	EthernetCounters(entityID uint16) (EthernetCounters, error)
}

type FECController interface {
	FECCounters(aniEntityID uint16) (FECCounters, error)
}

// XGSPONController is deliberately separate from the GPON GEM/FEC interfaces.
// Implementations must return monotonic hardware counters, not synthesized zeros.
type XGSPONController interface {
	XGSPONCounters(aniEntityID uint16) (XGSPONCounters, error)
}
