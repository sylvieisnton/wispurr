package wisp

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var connIDCounter uint64

const streamCacheSize = 256

func (c *wispConnection) maxPendingQueueBytes() int {
	if c != nil && c.config != nil && c.config.PendingQueueSize > 0 {
		return c.config.PendingQueueSize
	}
	return defaultPendingQueueBytes
}

func (c *wispConnection) close() {
	if !c.isClosed.CompareAndSwap(false, true) {
		return
	}
	c.netConn.Close()
	close(c.closeCh)

	c.pendingMutex.Lock()
	pending := c.pendingWrites
	c.pendingWrites = nil
	c.pendingBytes = 0
	c.pendingMutex.Unlock()
	for _, r := range pending {
		if r.buf != nil {
			c.config.ReadBufPool.Put(r.buf)
		}
		if r.done != nil {
			r.done <- net.ErrClosed
		}
	}
}

func (c *wispConnection) runWriter() {
	var bufs net.Buffers
	var pooled []*[]byte
	batch := make([]writeReq, 0, 16)

	for {
		c.pendingMutex.Lock()
		if len(c.pendingWrites) == 0 {
			c.writeActive = false
			c.pendingMutex.Unlock()
			return
		}
		batch, c.pendingWrites = c.pendingWrites, batch[:0]
		var batchBytes int
		for _, r := range batch {
			batchBytes += len(r.data)
		}
		c.pendingBytes -= batchBytes
		c.pendingMutex.Unlock()

		if cap(bufs) < len(batch) {
			bufs = make(net.Buffers, 0, len(batch))
			pooled = make([]*[]byte, 0, len(batch))
		} else {
			bufs = bufs[:0]
			pooled = pooled[:0]
		}
		for _, r := range batch {
			bufs = append(bufs, r.data)
			if r.buf != nil {
				pooled = append(pooled, r.buf)
			}
		}

		var err error
		if len(bufs) == 1 {
			err = writeAll(c.netConn, bufs[0])
		} else {
			_, err = bufs.WriteTo(c.netConn)
		}
		for _, p := range pooled {
			c.config.ReadBufPool.Put(p)
		}
		for _, r := range batch {
			if r.done != nil {
				r.done <- err
			}
		}
		if err != nil {
			c.pendingMutex.Lock()
			c.writeActive = false
			c.pendingMutex.Unlock()
			c.close()
			return
		}
	}
}

func (c *wispConnection) submitWrite(req writeReq) {
	if c.isClosed.Load() {
		if req.buf != nil {
			c.config.ReadBufPool.Put(req.buf)
		}
		if req.done != nil {
			req.done <- net.ErrClosed
		}
		return
	}
	c.pendingMutex.Lock()
	if c.pendingBytes+len(req.data) > c.maxPendingQueueBytes() {
		c.pendingMutex.Unlock()
		if req.buf != nil {
			c.config.ReadBufPool.Put(req.buf)
		}
		if req.done != nil {
			req.done <- net.ErrClosed
		}
		c.close()
		return
	}
	c.pendingWrites = append(c.pendingWrites, req)
	c.pendingBytes += len(req.data)
	if c.writeActive {
		c.pendingMutex.Unlock()
		return
	}
	c.writeActive = true
	c.pendingMutex.Unlock()
	go c.runWriter()
}

func (c *wispConnection) queueWrite(data []byte) {
	c.submitWrite(writeReq{data: data})
}

func (c *wispConnection) queueWritePooled(data []byte, buf *[]byte) {
	c.submitWrite(writeReq{data: data, buf: buf})
}

func (c *wispConnection) writeAndWait(data []byte) error {
	done := make(chan error, 1)
	c.submitWrite(writeReq{data: data, done: done})
	return <-done
}

func (c *wispConnection) handlePacket(packetType uint8, streamId uint32, payload []byte) {
	switch packetType {
	case packetTypeInfo:
		if c.isV2 {
			c.handleInfo(streamId, payload)
		}
	case packetTypeConnect:
		c.handleConnectPacket(streamId, payload)
	case packetTypeClose:
		c.handleClosePacket(streamId, payload)
	case twispExtensionID:
		if c.config.EnableTwisp && c.twispStreams != nil && len(payload) >= 4 {
			rows := binary.LittleEndian.Uint16(payload[0:2])
			cols := binary.LittleEndian.Uint16(payload[2:4])
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				ts.resize(rows, cols)
			}
		}
	}
}

func (c *wispConnection) handleConnectPacket(streamId uint32, payload []byte) {
	if len(payload) < 3 {
		c.sendClosePacket(streamId, closeReasonInvalidInfo)
		return
	}
	streamType := payload[0]
	portU16 := binary.LittleEndian.Uint16(payload[1:3])
	port := strconv.FormatUint(uint64(portU16), 10)
	hostname := string(payload[3:])
	if streamId == 0 || (portU16 == 0 && streamType != streamTypeTerm) || hostname == "" || !utf8.ValidString(hostname) {
		c.sendClosePacket(streamId, closeReasonInvalidInfo)
		return
	}

	c.config.Logger.Debug("creating stream", "ip", c.remoteIP, "streamId", streamId, "hostname", hostname, "port", port, "type", streamType)

	if c.config.FloodProtection != nil && c.config.FloodProtection.MaxConcurrentStreamsPerConnection > 0 {
		if c.streamCount.Load() >= int32(c.config.FloodProtection.MaxConcurrentStreamsPerConnection) {
			c.violation("per_ws_streams")
			c.sendClosePacket(streamId, closeReasonThrottled)
			return
		}
	}

	if c.globals != nil && c.globals.PerSource != nil && !c.globals.PerSource.Allow(c.remoteIP) {
		c.violation("per_source_rate")
		c.repAddSource("burstRate")
		c.config.Logger.Warn("flood block", "reason", "per_source_rate", "ip", c.remoteIP, "host", hostname, "port", port)
		c.sendClosePacket(streamId, closeReasonThrottled)
		return
	}

	if streamType == streamTypeTerm {
		c.handleTwispConnect(streamId, hostname)
		return
	}

	stream := &wispStream{
		wispConn:       c,
		streamId:       streamId,
		connReady:      make(chan struct{}),
		hostname:       strings.ToLower(strings.TrimSpace(hostname)),
		portNum:        int(portU16),
		pendingIngress: make([]ingressJob, 0, 16),
	}
	stream.isOpen.Store(true)

	if _, loaded := c.streams.LoadOrStore(streamId, stream); loaded {
		close(stream.connReady)
		c.sendClosePacket(streamId, closeReasonInvalidInfo)
		return
	}

	c.streamCount.Add(1)
	go stream.handleConnect(streamType, port, hostname)
}

func (c *wispConnection) handleTwispConnect(streamId uint32, command string) {
	if !c.config.EnableTwisp {
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.isV2 {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "v1_no_auth", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.config.PasswordAuth {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "no_auth_configured", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	if !c.twispAuthorized() {
		c.repAddSource("twispNoAuth")
		c.config.Logger.Warn("twisp blocked", "reason", "not_authenticated", "ip", c.remoteIP)
		c.sendClosePacket(streamId, closeReasonBlocked)
		return
	}
	go handleTwisp(c, streamId, command)
}

func (c *wispConnection) violation(reason string) {
	if c.config.FloodProtection == nil || c.config.FloodProtection.WsCloseAfterViolations <= 0 {
		return
	}
	n := c.violations.Add(1)
	if n >= int32(c.config.FloodProtection.WsCloseAfterViolations) {
		c.config.Logger.Warn("ws closed for violations", "ip", c.remoteIP, "violations", n, "lastReason", reason)
		c.close()
	}
}

func (c *wispConnection) repAddSource(reason string) {
	if c.globals != nil && c.globals.Reputation != nil {
		c.globals.Reputation.AddSource(c.remoteIP, reason)
	}
}

func (c *wispConnection) repAddDest(ip string, port int, reason string) {
	if c.globals != nil && c.globals.Reputation != nil {
		c.globals.Reputation.AddDest(ip, port, reason, net.ParseIP(c.remoteIP))
	}
}

func (c *wispConnection) handleDataPacket(streamId uint32, payload []byte, bufp *[]byte) bool {
	c.ingressBytes.Add(uint64(len(payload)))
	slot := &c.streamCache[streamId&(streamCacheSize-1)]
	stream := slot.Load()
	if stream == nil || stream.streamId != streamId {
		v, ok := c.streams.Load(streamId)
		if !ok {
			if c.twispStreams != nil {
				ts := c.twispStreams.get(streamId)
				if ts != nil && ts.isOpen.Load() {
					if err := ts.writePty(payload); err != nil {
						ts.close(closeReasonNetworkError)
					}
					return false
				}
			}
			c.sendClosePacket(streamId, closeReasonInvalidInfo)
			return false
		}
		stream = v.(*wispStream)
		slot.Store(stream)
	}

	if !stream.isOpen.Load() {
		return false
	}
	if c.globals != nil && c.globals.Bandwidth != nil && !c.globals.Bandwidth.Wait(c.closeCh, c.remoteIP, len(payload)) {
		return false
	}

	if !stream.connReadyDone.Load() {
		stream.pendingMutex.Lock()
		if !stream.connReadyDone.Load() {
			if stream.pendingBytes+len(payload) > 16*1024*1024 {
				stream.pendingMutex.Unlock()
				stream.close(closeReasonThrottled)
				return false
			}
			dataCopy := make([]byte, len(payload))
			copy(dataCopy, payload)
			stream.pendingData = append(stream.pendingData, dataCopy)
			stream.pendingBytes += len(dataCopy)
			stream.pendingMutex.Unlock()
			return false
		}
		stream.pendingMutex.Unlock()
	}

	if stream.streamType == streamTypeTCP && stream.ingressActive.Load() {
		if !stream.queueIngressOwned(payload, bufp) {
			return true
		}
		stream.bufferRemaining--
		if stream.bufferRemaining == 0 {
			stream.bufferRemaining = c.config.BufferRemainingLength
			c.sendPacket(streamId, stream.bufferRemaining)
		}
		return true
	}

	err := writeAll(stream.conn, payload)
	if err != nil {
		stream.close(closeReasonNetworkError)
		return false
	}

	if stream.streamType == streamTypeTCP {
		stream.bufferRemaining--
		if stream.bufferRemaining == 0 {
			stream.bufferRemaining = c.config.BufferRemainingLength
			c.sendPacket(streamId, stream.bufferRemaining)
		}
	}
	return false
}

func (c *wispConnection) twispAuthorized() bool {
	return c.isV2 && c.authenticated.Load()
}

func (c *wispConnection) handleClosePacket(streamId uint32, payload []byte) {
	if len(payload) < 1 {
		return
	}
	if streamId == 0 {
		c.close()
		return
	}

	v, ok := c.streams.Load(streamId)
	if !ok {
		if c.twispStreams != nil {
			ts := c.twispStreams.get(streamId)
			if ts != nil {
				go ts.close(closeReasonVoluntary)
			}
		}
		return
	}
	stream := v.(*wispStream)
	go stream.close(closeReasonVoluntary)
}

func (c *wispConnection) sendPacket(streamId uint32, bufferRemaining uint32) {
	if c.isClosed.Load() {
		return
	}
	buf := make([]byte, 11)
	buf[0] = 0x82
	buf[1] = 9
	buf[2] = packetTypeContinue
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	binary.LittleEndian.PutUint32(buf[7:11], bufferRemaining)
	c.queueWrite(buf)
}

func (c *wispConnection) sendClosePacket(streamId uint32, reason uint8) {
	if c.isClosed.Load() {
		return
	}
	c.queueWrite(buildClosePacket(streamId, reason))
}

func (c *wispConnection) sendClosePacketAndWait(streamId uint32, reason uint8) {
	if c.isClosed.Load() {
		return
	}
	_ = c.netConn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.writeAndWait(buildClosePacket(streamId, reason))
}

func buildClosePacket(streamId uint32, reason uint8) []byte {
	buf := make([]byte, 8)
	buf[0] = 0x82
	buf[1] = 6
	buf[2] = packetTypeClose
	buf[3] = byte(streamId)
	buf[4] = byte(streamId >> 8)
	buf[5] = byte(streamId >> 16)
	buf[6] = byte(streamId >> 24)
	buf[7] = reason
	return buf
}

func (c *wispConnection) writeRawPong(payload []byte) error {
	if c.isClosed.Load() {
		return nil
	}
	totalLen := len(payload)
	buf := make([]byte, 2+totalLen)
	buf[0] = 0x8A
	buf[1] = byte(totalLen)
	copy(buf[2:], payload)
	c.queueWrite(buf)
	return nil
}

func (c *wispConnection) deleteWispStream(streamId uint32) {
	c.streams.Delete(streamId)
	slot := &c.streamCache[streamId&(streamCacheSize-1)]
	if cached := slot.Load(); cached != nil && cached.streamId == streamId {
		slot.CompareAndSwap(cached, nil)
	}
	c.streamCount.Add(-1)
}

func (c *wispConnection) deleteAllWispStreams() {
	c.close()
	c.config.Logger.Info("connection closed", "ip", c.remoteIP)
	c.streams.Range(func(key, value any) bool {
		stream := value.(*wispStream)
		stream.close(closeReasonUnspecified)
		return true
	})
	if c.twispStreams != nil {
		c.twispStreams.mu.Lock()
		streams := make([]*twispStream, 0, len(c.twispStreams.streams))
		for _, ts := range c.twispStreams.streams {
			streams = append(streams, ts)
		}
		c.twispStreams.mu.Unlock()
		for _, ts := range streams {
			ts.close(closeReasonUnspecified)
		}
	}
	if c.globals != nil {
		c.globals.active.Delete(c.connID)
		c.globals.totalIngressBytes.Add(c.ingressBytes.Load())
		c.globals.totalEgressBytes.Add(c.egressBytes.Load())
		if c.globals.Connections != nil {
			c.globals.Connections.Release()
		}
		if c.globals.Signature != nil {
			c.globals.Signature.Forget(c.connID)
		}
	}
}
