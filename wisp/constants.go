package wisp

const (
	defaultPendingQueueBytes = 64 * 1024 * 1024

	packetTypeConnect  uint8 = 0x01
	packetTypeData     uint8 = 0x02
	packetTypeContinue uint8 = 0x03
	packetTypeClose    uint8 = 0x04
	packetTypeInfo     uint8 = 0x05

	streamTypeTCP  uint8 = 0x01
	streamTypeUDP  uint8 = 0x02
	streamTypeTerm uint8 = 0x03

	twispExtensionID uint8 = 0xF0

	wispMajorVersion         uint8 = 2
	wispMinorVersion         uint8 = 1
	extensionUDP             uint8 = 0x01
	extensionPasswordAuth    uint8 = 0x02
	extensionCertificateAuth uint8 = 0x03
	extensionMotd            uint8 = 0x04
	extensionStreamConfirm   uint8 = 0x05
	sigEd25519               uint8 = 0b00000001
	closeReasonUnspecified   uint8 = 0x01
	closeReasonVoluntary     uint8 = 0x02
	closeReasonNetworkError  uint8 = 0x03
	closeReasonIncompatible  uint8 = 0x04

	closeReasonInvalidInfo       uint8 = 0x41
	closeReasonUnreachable       uint8 = 0x42
	closeReasonTimeout           uint8 = 0x43
	closeReasonConnectionRefused uint8 = 0x44
	closeReasonTCPTimeout        uint8 = 0x47
	closeReasonBlocked           uint8 = 0x48
	closeReasonThrottled         uint8 = 0x49

	closeReasonClientError      uint8 = 0x81
	closeReasonAuthBadPassword  uint8 = 0xc0
	closeReasonAuthBadSignature uint8 = 0xc1
	closeReasonAuthRequired     uint8 = 0xc2
)
