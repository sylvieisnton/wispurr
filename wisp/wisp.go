package wisp

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxzan/gws"
)

func (cfg *Config) InitResolver() {
	cfg.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     cfg.DnsServers,
			Method:      cfg.DnsMethod,
			ResultOrder: cfg.DnsResultOrder,
		})
	cfg.Logger = newLogger(cfg.LogLevel)

	cfg.trustedProxyNets = cfg.trustedProxyNets[:0]
	for _, t := range cfg.TrustedProxies {
		entry := t
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				entry = fmt.Sprintf("%s/%d", entry, bits)
			}
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			cfg.trustedProxyNets = append(cfg.trustedProxyNets, n)
		}
	}
}

func NewWispHandler(config *Config) (http.HandlerFunc, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return createWispHandler(config), nil
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	handler, err := NewWispHandler(config)
	if err == nil {
		return handler
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid Wisp server configuration", http.StatusInternalServerError)
	}
}

func createWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()
	config.BuildGlobals()

	readBufSize := 15 + config.TcpBufferSize
	config.ReadBufPool = &sync.Pool{
		New: func() any {
			buf := make([]byte, readBufSize)
			return &buf
		},
	}

	config.Dialer = net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: config.WebsocketPermessageDeflate,
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			if config.NonWSResponse == "" {
				w.WriteHeader(http.StatusUpgradeRequired)
				return
			}
			_, _ = w.Write([]byte(config.NonWSResponse))
			return
		}

		var trusted []*net.IPNet
		if config.ParseRealIP {
			trusted = config.trustedProxyNets
		}
		remoteIP := ResolveClientIP(r, trusted, config.TrustedHeaders)
		if config.Globals != nil && config.Globals.ConnectionRate != nil && !config.Globals.ConnectionRate.Allow(remoteIP.String()) {
			w.Header().Set("Retry-After", strconv.Itoa(config.ConnectionWindowSeconds))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		if config.Globals != nil && config.Globals.Connections != nil {
			if !config.Globals.Connections.TryAcquire() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}

		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""
		if config.requiresV2() && !useV2 {
			if config.Globals != nil && config.Globals.Connections != nil {
				config.Globals.Connections.Release()
			}
			w.WriteHeader(http.StatusUpgradeRequired)
			return
		}

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
			if config.Globals != nil && config.Globals.Connections != nil {
				config.Globals.Connections.Release()
			}
			return
		}

		netConn := wsConn.NetConn()

		if tc, ok := netConn.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(config.SocketBufferSize)
			_ = tc.SetWriteBuffer(config.SocketBufferSize)
			_ = tc.SetNoDelay(true)
		}
		setTCPLowLatency(netConn)

		wc := &wispConnection{
			netConn:       netConn,
			closeCh:       make(chan struct{}),
			config:        config,
			twispStreams:  newTwisp(),
			isV2:          useV2,
			remoteIP:      remoteIP.String(),
			globals:       config.Globals,
			connID:        atomic.AddUint64(&connIDCounter, 1),
			pendingWrites: make([]writeReq, 0, 16),
		}
		if wc.globals != nil {
			wc.globals.active.Store(wc.connID, wc)
		}

		if useV2 {
			_ = wc.netConn.SetReadDeadline(time.Now().Add(time.Duration(config.HandshakeTimeoutSeconds) * time.Second))
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}

func (cfg *Config) requiresV2() bool {
	if cfg == nil {
		return false
	}
	return cfg.PasswordAuthRequired || cfg.EnableTwisp
}
