package wisp

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var plaintextWarned atomic.Bool

func checkPassword(logger Logger, stored, provided string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil
	}
	if !plaintextWarned.Swap(true) && logger != nil {
		logger.Warn("plaintext passwords in passwordUsers are deprecated; use bcrypt hashes ($2a$/$2b$)")
	}
	expBytes := []byte(stored)
	gotBytes := []byte(provided)
	return len(expBytes) == len(gotBytes) && subtle.ConstantTimeCompare(expBytes, gotBytes) == 1
}

var errorInvalid = errors.New("invalid wisp v2 payload")

func (c *wispConnection) buildServerInfoPacket() []byte {
	var extensions []byte

	if c.config.AllowUDP {
		extensions = addExtension(extensions, extensionUDP, nil)
	}

	if c.config.PasswordAuth {
		var meta [1]byte
		if c.config.PasswordAuthRequired {
			meta[0] = 1
		}
		extensions = addExtension(extensions, extensionPasswordAuth, meta[:])
	}

	if c.config.Motd != "" {
		extensions = addExtension(extensions, extensionMotd, []byte(c.config.Motd))
	}

	payload := make([]byte, 5+2+len(extensions))
	payload[0] = packetTypeInfo
	payload[5] = wispMajorVersion
	payload[6] = wispMinorVersion
	copy(payload[7:], extensions)

	return payload
}

func addExtension(buf []byte, id uint8, metadata []byte) []byte {
	entry := make([]byte, 5+len(metadata))
	entry[0] = id
	binary.LittleEndian.PutUint32(entry[1:5], uint32(len(metadata)))
	if len(metadata) > 0 {
		copy(entry[5:], metadata)
	}
	return append(buf, entry...)
}

func parseClientInfo(payload []byte) (*Extensions, error) {
	if len(payload) < 2 {
		return nil, errorInvalid
	}

	exts := &Extensions{}
	data := payload[2:]

	for len(data) >= 5 {
		extID := data[0]
		extLen := binary.LittleEndian.Uint32(data[1:5])
		data = data[5:]

		if uint32(len(data)) < extLen {
			return nil, errorInvalid
		}

		meta := data[:extLen]
		data = data[extLen:]

		switch extID {
		case extensionUDP:
			exts.udp = true

		case extensionPasswordAuth:
			if len(meta) < 1 {
				return nil, errorInvalid
			}
			usernameLen := int(meta[0])
			if len(meta) < 1+usernameLen {
				return nil, errorInvalid
			}
			exts.passwordUsername = string(meta[1 : 1+usernameLen])
			exts.passwordPassword = string(meta[1+usernameLen:])

		case extensionCertificateAuth:
			if len(meta) < 1 {
				return nil, errorInvalid
			}
			usernameLen := int(meta[0])
			if len(meta) < 1+usernameLen+1+32 {
				return nil, errorInvalid
			}
			exts.certificateUsername = string(meta[1 : 1+usernameLen])
			pos := 1 + usernameLen
			exts.certificateSelected = meta[pos]
			pos++
			copy(exts.certificatePubkeyHash[:], meta[pos:pos+32])
			pos += 32
			if pos < len(meta) {
				exts.certificateSig = make([]byte, len(meta)-pos)
				copy(exts.certificateSig, meta[pos:])
			}

		case extensionStreamConfirm:
			exts.streamConfirm = true
		}
	}
	if len(data) != 0 {
		return nil, errorInvalid
	}

	return exts, nil
}

func (c *wispConnection) v2Handshake() {
	c.handshakeDone = make(chan struct{})

	infoPayload := c.buildServerInfoPacket()
	c.sendRawFrame(infoPayload)

	c.readLoop()
}

func (c *wispConnection) handleInfo(streamId uint32, payload []byte) {
	if streamId != 0 {
		return
	}
	if c.handshakeDone == nil {
		return
	}
	if len(payload) < 2 || payload[0] != wispMajorVersion {
		c.sendClosePacketAndWait(0, closeReasonIncompatible)
		c.close()
		return
	}

	clientExts, err := parseClientInfo(payload)
	if err != nil {
		c.sendClosePacketAndWait(0, closeReasonIncompatible)
		c.close()
		return
	}

	authRequired := c.config.PasswordAuthRequired
	authPassed := false

	if c.config.PasswordAuth && clientExts.passwordUsername != "" {
		expectedPassword, userExists := c.config.PasswordUsers[clientExts.passwordUsername]
		if userExists && checkPassword(c.config.Logger, expectedPassword, clientExts.passwordPassword) {
			authPassed = true
		} else {
			c.sendClosePacketAndWait(0, closeReasonAuthBadPassword)
			c.close()
			return
		}
	}

	if authRequired && !authPassed {
		c.sendClosePacketAndWait(0, closeReasonAuthRequired)
		c.close()
		return
	}

	c.authenticated.Store(authPassed)
	c.streamConfirm = clientExts.streamConfirm

	c.sendPacket(0, c.config.BufferRemainingLength)

	_ = c.netConn.SetReadDeadline(time.Time{})
	close(c.handshakeDone)
	c.handshakeDone = nil
}
func (c *wispConnection) sendRawFrame(packet []byte) {
	totalLen := len(packet)
	var frame []byte

	if totalLen <= 125 {
		frame = make([]byte, 2+totalLen)
		frame[0] = 0x82
		frame[1] = byte(totalLen)
		copy(frame[2:], packet)
	} else if totalLen <= 65535 {
		frame = make([]byte, 4+totalLen)
		frame[0] = 0x82
		frame[1] = 126
		frame[2] = byte(totalLen >> 8)
		frame[3] = byte(totalLen)
		copy(frame[4:], packet)
	} else {
		frame = make([]byte, 10+totalLen)
		frame[0] = 0x82
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:10], uint64(totalLen))
		copy(frame[10:], packet)
	}

	c.queueWrite(frame)
}
