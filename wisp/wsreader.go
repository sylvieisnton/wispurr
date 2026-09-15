package wisp

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"
)

const wsPayloadPoolSize = 256 * 1024

var wsPayloadPool = sync.Pool{
	New: func() any {
		buf := make([]byte, wsPayloadPoolSize)
		return &buf
	},
}

func getWSPayloadBuf(size int) *[]byte {
	bufp := wsPayloadPool.Get().(*[]byte)
	if cap(*bufp) < size {
		nb := make([]byte, size)
		return &nb
	}
	*bufp = (*bufp)[:size]
	return bufp
}

func putWSPayloadBuf(bufp *[]byte) {
	if bufp == nil || cap(*bufp) == 0 || cap(*bufp) > wsPayloadPoolSize {
		return
	}
	wsPayloadPool.Put(bufp)
}

const readFrameBufSize = 14

type frameReader struct {
	conn net.Conn
	buf  []byte
	r, w int
}

func newFrameReader(conn net.Conn) *frameReader {
	return &frameReader{
		conn: conn,
		buf:  make([]byte, readFrameBufSize),
	}
}

func (f *frameReader) fill(min int) error {
	if f.w-f.r >= min {
		return nil
	}
	if f.r > 0 {
		copy(f.buf, f.buf[f.r:f.w])
		f.w -= f.r
		f.r = 0
	}
	for f.w-f.r < min {
		n, err := f.conn.Read(f.buf[f.w:])
		if n > 0 {
			f.w += n
		}
		if err != nil {
			if f.w-f.r >= min {
				return nil
			}
			return err
		}
	}
	return nil
}

func (f *frameReader) peek(n int) ([]byte, error) {
	if err := f.fill(n); err != nil {
		return nil, err
	}
	return f.buf[f.r : f.r+n], nil
}

func (f *frameReader) consume(n int) {
	f.r += n
	if f.r == f.w {
		f.r, f.w = 0, 0
	}
}

func (f *frameReader) readPayload(dst []byte) error {
	if buffered := f.w - f.r; buffered > 0 {
		if buffered >= len(dst) {
			copy(dst, f.buf[f.r:f.r+len(dst)])
			f.consume(len(dst))
			return nil
		}
		copy(dst, f.buf[f.r:f.w])
		dst = dst[buffered:]
		f.r, f.w = 0, 0
	}
	_, err := io.ReadFull(f.conn, dst)
	return err
}

func (c *wispConnection) readLoop() {
	defer c.deleteAllWispStreams()
	reader := newFrameReader(c.netConn)
	var fragmentedOpcode uint8
	var fragmented []byte

	for {
		hdr, err := reader.peek(2)
		if err != nil {
			return
		}

		b0 := hdr[0]
		b1 := hdr[1]
		fin := b0&0x80 != 0
		rsv := b0 & 0x70
		opcode := b0 & 0x0F
		masked := b1&0x80 != 0
		lengthCode := b1 & 0x7F

		if rsv != 0 || !masked {
			c.sendWSClose(1002)
			return
		}

		headerLen := 2
		switch {
		case lengthCode == 126:
			headerLen += 2
		case lengthCode == 127:
			headerLen += 8
		case lengthCode <= 125:
		}
		headerLen += 4

		hdr, err = reader.peek(headerLen)
		if err != nil {
			return
		}

		var payloadLen uint64
		switch {
		case lengthCode <= 125:
			payloadLen = uint64(lengthCode)
		case lengthCode == 126:
			payloadLen = uint64(binary.BigEndian.Uint16(hdr[2:4]))
		case lengthCode == 127:
			payloadLen = binary.BigEndian.Uint64(hdr[2:10])
			if hdr[2]&0x80 != 0 {
				c.sendWSClose(1002)
				return
			}
		}

		isControlFrame := opcode >= 0x8
		if isControlFrame && (!fin || payloadLen > 125) {
			c.sendWSClose(1002)
			return
		}

		var maskKey [4]byte
		copy(maskKey[:], hdr[headerLen-4:headerLen])
		reader.consume(headerLen)

		if payloadLen > c.maxPayloadSize() {
			c.sendWSClose(1009)
			return
		}

		bufp := getWSPayloadBuf(int(payloadLen))
		payload := (*bufp)[:payloadLen]

		if payloadLen > 0 {
			if err := reader.readPayload(payload); err != nil {
				putWSPayloadBuf(bufp)
				return
			}
		}

		if payloadLen > 0 {
			maskXOR(payload, maskKey)
		}

		keep := false
		switch opcode {
		case 0x0:
			if fragmentedOpcode == 0 {
				putWSPayloadBuf(bufp)
				c.sendWSClose(1002)
				return
			}
			if uint64(len(fragmented))+payloadLen > c.maxPayloadSize() {
				putWSPayloadBuf(bufp)
				c.sendWSClose(1009)
				return
			}
			fragmented = append(fragmented, payload...)
			putWSPayloadBuf(bufp)
			if fin {
				c.handleWispFrame(fragmented, nil)
				fragmented = nil
				fragmentedOpcode = 0
			}
			continue

		case 0x2:
			if fragmentedOpcode != 0 {
				putWSPayloadBuf(bufp)
				c.sendWSClose(1002)
				return
			}
			if !fin {
				fragmentedOpcode = opcode
				fragmented = append(fragmented[:0], payload...)
				putWSPayloadBuf(bufp)
				continue
			}
			keep = c.handleWispFrame(payload, bufp)

		case 0x1:
			putWSPayloadBuf(bufp)
			c.sendWSClose(1003)
			return

		case 0x9:
			_ = c.writeRawPong(payload)

		case 0xA:

		case 0x8:
			if len(payload) == 1 {
				putWSPayloadBuf(bufp)
				c.sendWSClose(1002)
				return
			}
			if len(payload) >= 2 {
				code := binary.BigEndian.Uint16(payload[:2])
				c.sendWSClose(code)
			} else {
				c.sendWSClose(1000)
			}
			putWSPayloadBuf(bufp)
			return
		default:
			putWSPayloadBuf(bufp)
			c.sendWSClose(1002)
			return
		}

		if !keep {
			putWSPayloadBuf(bufp)
		}
	}
}

const DefaultMaxPayloadSize = 256 * 1024

func (c *wispConnection) maxPayloadSize() uint64 {
	if c != nil && c.config != nil && c.config.MaxMessageSize > 0 {
		return uint64(c.config.MaxMessageSize)
	}
	return DefaultMaxPayloadSize
}

func (c *wispConnection) handleWispFrame(packet []byte, bufp *[]byte) bool {
	if len(packet) < 5 {
		return false
	}

	packetType := packet[0]
	streamId := binary.LittleEndian.Uint32(packet[1:5])
	payload := packet[5:]

	if c.isV2 && c.handshakeDone != nil {
		select {
		case <-c.handshakeDone:
		default:
			if packetType == packetTypeInfo {
				c.handlePacket(packetType, streamId, payload)
				return false
			}
			if packetType == packetTypeClose && streamId == 0 {
				c.handlePacket(packetType, streamId, payload)
				return false
			}
			return false
		}
	}

	if packetType == packetTypeData {
		return c.handleDataPacket(streamId, payload, bufp)
	}
	c.handlePacket(packetType, streamId, payload)
	return false
}

func maskXOR(b []byte, key [4]byte) {
	maskKey := *(*uint32)(unsafe.Pointer(&key[0]))
	key64 := uint64(maskKey)<<32 | uint64(maskKey)

	for len(b) >= 64 {
		p := unsafe.Pointer(&b[0])
		*(*uint64)(p) ^= key64
		*(*uint64)(unsafe.Add(p, 8)) ^= key64
		*(*uint64)(unsafe.Add(p, 16)) ^= key64
		*(*uint64)(unsafe.Add(p, 24)) ^= key64
		*(*uint64)(unsafe.Add(p, 32)) ^= key64
		*(*uint64)(unsafe.Add(p, 40)) ^= key64
		*(*uint64)(unsafe.Add(p, 48)) ^= key64
		*(*uint64)(unsafe.Add(p, 56)) ^= key64
		b = b[64:]
	}

	for len(b) >= 8 {
		*(*uint64)(unsafe.Pointer(&b[0])) ^= key64
		b = b[8:]
	}

	for i := range b {
		b[i] ^= key[i&3]
	}
}

func (c *wispConnection) sendWSClose(code uint16) {
	buf := make([]byte, 4)
	buf[0] = 0x88
	buf[1] = 2
	binary.BigEndian.PutUint16(buf[2:4], code)
	_ = c.netConn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.writeAndWait(buf)
}
