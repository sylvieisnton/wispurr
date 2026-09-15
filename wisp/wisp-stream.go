package wisp

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	ingressPoolNone ingressPool = iota
	ingressPoolWS
	ingressPoolCopy
)

func releaseIngressJob(j ingressJob) {
	if j.bufp == nil {
		return
	}
	switch j.pool {
	case ingressPoolWS:
		putWSPayloadBuf(j.bufp)
	case ingressPoolCopy:
		putIngressBuf(j.bufp)
	}
}

var ingressBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 256*1024)
		return &buf
	},
}

func getIngressBuf(size int) *[]byte {
	bufp := ingressBufPool.Get().(*[]byte)
	if cap(*bufp) < size {
		nb := make([]byte, size)
		return &nb
	}
	*bufp = (*bufp)[:size]
	return bufp
}

func putIngressBuf(bufp *[]byte) {
	if bufp == nil || cap(*bufp) == 0 {
		return
	}
	ingressBufPool.Put(bufp)
}

const dnsLookupTimeout = 10 * time.Second

func NormalizeTargetHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func (s *wispStream) handleConnect(streamType uint8, port string, hostname string) {
	defer s.signalConnReady()

	cfg := s.wispConn.config
	s.hostname = NormalizeTargetHostname(hostname)

	if len(cfg.Whitelist.Hostnames) > 0 {
		if _, ok := cfg.Whitelist.Hostnames[s.hostname]; !ok {
			s.close(closeReasonBlocked)
			return
		}
	} else if len(cfg.Blacklist.Hostnames) > 0 {
		if _, ok := cfg.Blacklist.Hostnames[s.hostname]; ok {
			s.close(closeReasonBlocked)
			return
		}
	}

	portU16 := uint16(s.portNum)
	if len(cfg.Whitelist.Ports) > 0 {
		if _, ok := cfg.Whitelist.Ports[portU16]; !ok {
			cfg.Logger.Warn("port block: not in whitelist", "ip", s.wispConn.remoteIP, "host", s.hostname, "port", port)
			s.close(closeReasonBlocked)
			return
		}
	} else if len(cfg.Blacklist.Ports) > 0 {
		if _, ok := cfg.Blacklist.Ports[portU16]; ok {
			cfg.Logger.Warn("port block: in blacklist", "ip", s.wispConn.remoteIP, "host", s.hostname, "port", port)
			s.close(closeReasonBlocked)
			return
		}
	}

	policy := PolicyFromConfig(cfg)

	resolvedHostname := hostname
	if ip := net.ParseIP(hostname); ip != nil {
		if !cfg.AllowDirectIP {
			cfg.Logger.Warn("egress block: direct IP", "ip", s.wispConn.remoteIP, "dstIP", ip.String(), "port", port)
			s.close(closeReasonBlocked)
			return
		}
		if ok, reason := policy.Evaluate(ip); !ok {
			cfg.Logger.Warn("egress block", "ip", s.wispConn.remoteIP, "dstIP", ip.String(), "port", port, "reason", reason)
			s.close(closeReasonBlocked)
			return
		}
		resolvedHostname = ip.String()
	} else if cfg.DNSCache != nil {
		if _, whitelisted := cfg.Whitelist.Hostnames[hostname]; !whitelisted {
			ips, err := cfg.DNSCache.LookupIPAddr(context.Background(), hostname)
			if err != nil {
				s.close(closeReasonUnreachable)
				return
			}
			if len(ips) == 0 {
				s.close(closeReasonUnreachable)
				return
			}
			pickedReason := ""
			picked := false
			for _, ipa := range ips {
				if ok, reason := policy.Evaluate(ipa.IP); ok {
					resolvedHostname = ipa.IP.String()
					pickedReason = ""
					picked = true
					break
				} else {
					pickedReason = reason
				}
			}
			if !picked {
				cfg.Logger.Warn("egress block", "ip", s.wispConn.remoteIP, "host", hostname, "port", port, "reason", pickedReason)
				s.close(closeReasonBlocked)
				return
			}
		}
	}

	c := s.wispConn

	// Per-destination rate caps.
	dstKey := net.JoinHostPort(resolvedHostname, port)
	if c.globals != nil {
		if c.globals.PerDestSec != nil && !c.globals.PerDestSec.Allow(dstKey) {
			c.violation("per_dest_sec")
			c.repAddSource("burstRate")
			c.repAddDest(resolvedHostname, s.portNum, "burstRate")
			cfg.Logger.Warn("flood block", "reason", "per_dest_sec", "ip", c.remoteIP, "dstIP", resolvedHostname, "port", port)
			s.close(closeReasonThrottled)
			return
		}
		if c.globals.PerDestMin != nil && !c.globals.PerDestMin.Allow(dstKey) {
			c.violation("per_dest_min")
			cfg.Logger.Warn("flood block", "reason", "per_dest_min", "ip", c.remoteIP, "dstIP", resolvedHostname, "port", port)
			s.close(closeReasonThrottled)
			return
		}
	}

	// Reputation-strict destination check.
	if c.globals != nil && c.globals.Reputation != nil {
		ds := c.globals.Reputation.DestScore(resolvedHostname, s.portNum)
		if c.globals.Reputation.Tier(ds) == TierStrict {
			c.repAddSource("requestKnownBadDest")
			cfg.Logger.Warn("flood block", "reason", "dest_reputation_strict", "ip", c.remoteIP, "dstIP", resolvedHostname, "port", port)
			s.close(closeReasonBlocked)
			return
		}
	}

	// In-flight SYN cap.
	synAcquired := false
	if c.globals != nil && c.globals.InFlightSyns != nil && streamType == streamTypeTCP {
		if !c.globals.InFlightSyns.TryAcquire() {
			c.violation("in_flight_syns")
			cfg.Logger.Warn("flood block", "reason", "in_flight_syns", "ip", c.remoteIP, "dstIP", resolvedHostname, "port", port)
			s.close(closeReasonThrottled)
			return
		}
		synAcquired = true
	}

	s.streamType = streamType
	s.bufferRemaining = cfg.BufferRemainingLength

	destination := net.JoinHostPort(resolvedHostname, port)

	var err error
	switch streamType {
	case streamTypeTCP:
		if cfg.Proxy != "" {
			proxyURL := cfg.Proxy
			proxyURL = strings.Replace(proxyURL, "socks5h://", "socks5://", 1)
			proxyURL = strings.Replace(proxyURL, "socks4a://", "socks4://", 1)
			dialer, proxyErr := proxy.SOCKS5("tcp", stripScheme(proxyURL), nil, proxy.Direct)
			if proxyErr != nil {
				cfg.Logger.Warn("proxy dialer creation failed", "ip", s.wispConn.remoteIP, "error", proxyErr)
				if synAcquired {
					c.globals.InFlightSyns.Release()
				}
				s.close(closeReasonNetworkError)
				return
			}
			s.conn, err = dialer.Dial("tcp", destination)
		} else {
			s.conn, err = cfg.Dialer.Dial("tcp", destination)
		}
	case streamTypeUDP:
		if cfg.Proxy != "" || !cfg.AllowUDP {
			if synAcquired {
				c.globals.InFlightSyns.Release()
			}
			s.close(closeReasonBlocked)
			return
		}
		s.conn, err = net.Dial("udp", destination)
	default:
		if synAcquired {
			c.globals.InFlightSyns.Release()
		}
		s.close(closeReasonInvalidInfo)
		return
	}

	if synAcquired {
		c.globals.InFlightSyns.Release()
	}

	if c.globals != nil && c.globals.Signature != nil && streamType == streamTypeTCP {
		det := c.globals.Signature.For(c.connID, resolvedHostname, s.portNum)
		det.Record(err == nil)
		if det.Match() {
			c.repAddSource("synSignature")
			c.repAddDest(resolvedHostname, s.portNum, "synSignature")
			cfg.Logger.Warn("syn-flood signature matched; closing WS",
				"ip", c.remoteIP, "dstIP", resolvedHostname, "port", port)
			if err == nil && s.conn != nil {
				s.conn.Close()
			}
			s.close(closeReasonBlocked)
			c.close()
			return
		}
	}

	if err != nil {
		cfg.Logger.Warn("stream connection failed", "ip", s.wispConn.remoteIP, "hostname", hostname, "port", port, "error", err)
		s.close(mapDialError(err))
		return
	}

	if streamType == streamTypeTCP {
		if tc, ok := s.conn.(*net.TCPConn); ok {
			tc.SetNoDelay(cfg.TcpNoDelay)
			tc.SetReadBuffer(4 << 20)
			tc.SetWriteBuffer(4 << 20)
		}
		setTCPLowLatency(s.conn)
	}

	if s.wispConn.streamConfirm && streamType == streamTypeTCP {
		s.wispConn.sendPacket(s.streamId, s.bufferRemaining)
	}

	s.pendingMutex.Lock()
	pending := s.pendingData
	s.pendingData = nil
	s.pendingBytes = 0
	s.pendingMutex.Unlock()

	for _, data := range pending {
		if !s.isOpen.Load() {
			return
		}
		if _, err := s.conn.Write(data); err != nil {
			s.close(closeReasonNetworkError)
			return
		}
	}

	if streamType == streamTypeTCP {
		s.ingressActive.Store(true)
	}

	s.signalConnReady()

	s.readFromConnection()
}

func stripScheme(url string) string {
	if idx := strings.Index(url, "://"); idx >= 0 {
		return url[idx+3:]
	}
	return url
}

func (s *wispStream) runIngressWriter() {
	var bufs net.Buffers
	var jobs []ingressJob
	batch := make([]ingressJob, 0, 16)

	for {
		s.pendingIngMu.Lock()
		if len(s.pendingIngress) == 0 {
			s.ingressWriting = false
			s.pendingIngMu.Unlock()
			return
		}
		batch, s.pendingIngress = s.pendingIngress, batch[:0]
		var batchBytes int
		for _, j := range batch {
			batchBytes += len(j.payload)
		}
		s.pendingIngBytes -= batchBytes
		s.pendingIngMu.Unlock()

		if cap(bufs) < len(batch) {
			bufs = make(net.Buffers, 0, len(batch))
			jobs = make([]ingressJob, 0, len(batch))
		} else {
			bufs = bufs[:0]
			jobs = jobs[:0]
		}
		for _, j := range batch {
			bufs = append(bufs, j.payload)
			jobs = append(jobs, j)
		}

		if !s.isOpen.Load() {
			for i := range jobs {
				releaseIngressJob(jobs[i])
			}
			s.pendingIngMu.Lock()
			s.ingressWriting = false
			s.pendingIngMu.Unlock()
			return
		}

		var err error
		if len(bufs) == 1 {
			_, err = s.conn.Write(bufs[0])
		} else {
			_, err = bufs.WriteTo(s.conn)
		}
		for i := range jobs {
			releaseIngressJob(jobs[i])
		}
		if err != nil {
			s.pendingIngMu.Lock()
			s.ingressWriting = false
			s.pendingIngMu.Unlock()
			s.close(closeReasonNetworkError)
			return
		}
	}
}

func (s *wispStream) submitIngress(job ingressJob) bool {
	if !s.ingressActive.Load() || !s.isOpen.Load() {
		releaseIngressJob(job)
		return false
	}
	s.pendingIngMu.Lock()
	if s.pendingIngBytes+len(job.payload) > maxPendingQueueBytes {
		s.pendingIngMu.Unlock()
		releaseIngressJob(job)
		s.close(closeReasonThrottled)
		return false
	}
	s.pendingIngress = append(s.pendingIngress, job)
	s.pendingIngBytes += len(job.payload)
	if s.ingressWriting {
		s.pendingIngMu.Unlock()
		return true
	}
	s.ingressWriting = true
	s.pendingIngMu.Unlock()
	s.runIngressWriter()
	return true
}

func (s *wispStream) queueIngressOwned(payload []byte, bufp *[]byte) bool {
	if !s.ingressActive.Load() || !s.isOpen.Load() {
		putWSPayloadBuf(bufp)
		return false
	}
	return s.submitIngress(ingressJob{payload: payload, bufp: bufp, pool: ingressPoolWS})
}

func (s *wispStream) signalConnReady() {
	if s.connReadyDone.CompareAndSwap(false, true) {
		close(s.connReady)
	}
}

func (s *wispStream) readFromConnection() {
	const maxHeaderLen = 15

	pool := s.wispConn.config.ReadBufPool
	streamId := s.streamId

	bufp := pool.Get().(*[]byte)

	for {
		buf := *bufp
		n, err := s.conn.Read(buf[maxHeaderLen:])
		if n > 0 {
			totalPayload := 5 + n
			var frameStart int

			if totalPayload <= 125 {
				frameStart = maxHeaderLen - 7
				buf[frameStart] = 0x82
				buf[frameStart+1] = byte(totalPayload)
			} else if totalPayload <= 65535 {
				frameStart = maxHeaderLen - 9
				buf[frameStart] = 0x82
				buf[frameStart+1] = 126
				buf[frameStart+2] = byte(totalPayload >> 8)
				buf[frameStart+3] = byte(totalPayload)
			} else {
				frameStart = 0
				buf[0] = 0x82
				buf[1] = 127
				buf[2] = byte(totalPayload >> 56)
				buf[3] = byte(totalPayload >> 48)
				buf[4] = byte(totalPayload >> 40)
				buf[5] = byte(totalPayload >> 32)
				buf[6] = byte(totalPayload >> 24)
				buf[7] = byte(totalPayload >> 16)
				buf[8] = byte(totalPayload >> 8)
				buf[9] = byte(totalPayload)
			}

			wispStart := maxHeaderLen - 5
			buf[wispStart] = packetTypeData
			buf[wispStart+1] = byte(streamId)
			buf[wispStart+2] = byte(streamId >> 8)
			buf[wispStart+3] = byte(streamId >> 16)
			buf[wispStart+4] = byte(streamId >> 24)

			frame := buf[frameStart : maxHeaderLen+n]
			handoff := bufp
			bufp = pool.Get().(*[]byte)
			s.wispConn.queueWritePooled(frame, handoff)
		}
		if err != nil {
			pool.Put(bufp)
			if err == io.EOF {
				s.close(closeReasonVoluntary)
			} else {
				s.wispConn.config.Logger.Warn("stream read error", "ip", s.wispConn.remoteIP, "hostname", s.hostname, "error", err)
				s.close(closeReasonNetworkError)
			}
			return
		}
	}
}

func (s *wispStream) close(reason uint8) {
	if !s.isOpen.CompareAndSwap(true, false) {
		return
	}

	s.signalConnReady()

	s.wispConn.deleteWispStream(s.streamId)

	if s.conn != nil {
		s.conn.Close()
	}

	if s.ingressActive.Load() {
		s.ingressActive.Store(false)
		s.pendingIngMu.Lock()
		if !s.ingressWriting {
			drained := s.pendingIngress
			s.pendingIngress = nil
			s.pendingIngMu.Unlock()
			for _, j := range drained {
				releaseIngressJob(j)
			}
		} else {
			s.pendingIngMu.Unlock()
		}
	}

	s.wispConn.sendClosePacket(s.streamId, reason)
}

func mapDialError(err error) uint8 {
	if err == nil {
		return closeReasonUnspecified
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") {
		return closeReasonConnectionRefused
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "no address") {
		return closeReasonUnreachable
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return closeReasonTimeout
	}
	if strings.Contains(errStr, "network is unreachable") || strings.Contains(errStr, "host is unreachable") {
		return closeReasonUnreachable
	}

	return closeReasonNetworkError
}
