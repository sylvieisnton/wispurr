package wisp

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FilterSet struct {
	Hostnames map[string]struct{}
	Ports     map[uint16]struct{}
}

func (f *FilterSet) UnmarshalJSON(data []byte) error {
	if f.Hostnames == nil {
		f.Hostnames = map[string]struct{}{}
	}
	if f.Ports == nil {
		f.Ports = map[uint16]struct{}{}
	}

	var raw struct {
		Hostnames json.RawMessage `json:"hostnames"`
		Ports     json.RawMessage `json:"ports"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		if name != "hostnames" && name != "ports" {
			return fmt.Errorf("unknown filter field %q", name)
		}
	}

	if len(raw.Hostnames) > 0 {
		var arr []string
		if err := json.Unmarshal(raw.Hostnames, &arr); err == nil {
			for _, h := range arr {
				host := NormalizeTargetHostname(h)
				if host == "" {
					return fmt.Errorf("hostname filter cannot be empty")
				}
				f.Hostnames[host] = struct{}{}
			}
		} else {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw.Hostnames, &obj); err != nil {
				return fmt.Errorf("hostnames: expected array of strings, got %s", string(raw.Hostnames))
			}
			for h := range obj {
				host := NormalizeTargetHostname(h)
				if host == "" {
					return fmt.Errorf("hostname filter cannot be empty")
				}
				f.Hostnames[host] = struct{}{}
			}
		}
	}

	if len(raw.Ports) > 0 {
		var arr []interface{}
		if err := json.Unmarshal(raw.Ports, &arr); err == nil {
			for _, p := range arr {
				switch v := p.(type) {
				case float64:
					port, err := validPortNumber(v)
					if err != nil {
						return err
					}
					f.Ports[port] = struct{}{}
				case []interface{}:
					if len(v) != 2 {
						return fmt.Errorf("ports range must have exactly 2 elements")
					}
					start, ok1 := v[0].(float64)
					end, ok2 := v[1].(float64)
					if !ok1 || !ok2 {
						return fmt.Errorf("ports range elements must be numbers")
					}
					if _, err := validPortNumber(start); err != nil {
						return err
					}
					if _, err := validPortNumber(end); err != nil {
						return err
					}
					if end < start {
						start, end = end, start
					}
					for i := int(start); i <= int(end); i++ {
						f.Ports[uint16(i)] = struct{}{}
					}
				default:
					return fmt.Errorf("port entry must be number or [start, end]")
				}
			}
		} else {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw.Ports, &obj); err != nil {
				return fmt.Errorf("ports: expected array, got %s", string(raw.Ports))
			}
			for k := range obj {
				n, perr := strconv.ParseUint(k, 10, 16)
				if perr != nil || n == 0 {
					return fmt.Errorf("ports: object key %q is not a valid port number", k)
				}
				f.Ports[uint16(n)] = struct{}{}
			}
		}
	}

	return nil
}

type Config struct {
	Port int `json:"port"`

	AllowTCP bool `json:"allowTCP"`
	AllowUDP bool `json:"allowUDP"`

	AllowDirectIP    bool `json:"allowDirectIP"`
	AllowPrivateIPs  bool `json:"allowPrivateIPs"`
	AllowLoopbackIPs bool `json:"allowLoopbackIPs"`

	TcpBufferSize    int  `json:"tcpBufferSize"`
	TcpNoDelay       bool `json:"tcpNoDelay"`
	SocketBufferSize int  `json:"socketBufferSize"`
	PendingQueueSize int  `json:"pendingQueueSize"`

	Blacklist FilterSet `json:"blacklist"`
	Whitelist FilterSet `json:"whitelist"`

	WebsocketPermessageDeflate bool `json:"websocketPermessageDeflate"`

	DnsServers     []string `json:"dnsServers"`
	DnsMethod      string   `json:"dnsMethod"`
	DnsResultOrder string   `json:"dnsResultOrder"`

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2                bool              `json:"enableV2"`
	HandshakeTimeoutSeconds int               `json:"handshakeTimeoutSeconds"`
	Motd                    string            `json:"motd"`
	PasswordAuth            bool              `json:"passwordAuth"`
	PasswordAuthRequired    bool              `json:"passwordAuthRequired"`
	PasswordUsers           map[string]string `json:"passwordUsers"`

	ParseRealIP    bool     `json:"parseRealIP"`
	TrustedProxies []string `json:"trustedProxies"`
	TrustedHeaders []string `json:"trustedHeaders"`
	NonWSResponse  string   `json:"nonWSResponse"`

	trustedProxyNets []*net.IPNet

	LogLevel string `json:"logLevel"`

	Proxy                   string `json:"proxy"`
	MaxMessageSize          int    `json:"maxMessageSize"`
	StaticDir               string `json:"staticDir"`
	BandwidthLimitKbps      int    `json:"bandwidthLimitKbps"`
	ConnectionsLimitPerIP   int    `json:"connectionsLimitPerIP"`
	ConnectionWindowSeconds int    `json:"connectionWindowSeconds"`

	BufferRemainingLength uint32 `json:"bufferRemainingLength"`

	FloodProtection *FloodProtectionConfig `json:"floodProtection"`
	Reputation      *ReputationConfig      `json:"reputation"`

	Logger      Logger     `json:"-"`
	DNSCache    *DNSCache  `json:"-"`
	ReadBufPool *sync.Pool `json:"-"`
	Dialer      net.Dialer `json:"-"`
	Globals     *Globals   `json:"-"`
}

type FloodProtectionConfig struct {
	Enabled                           bool `json:"enabled"`
	MaxConnectsPerSourceIPPerSecond   int  `json:"maxConnectsPerSourceIPPerSecond"`
	MaxConnectsPerDestPerSecond       int  `json:"maxConnectsPerDestPerSecond"`
	MaxConnectsPerDestPerMinute       int  `json:"maxConnectsPerDestPerMinute"`
	MaxInFlightSyns                   int  `json:"maxInFlightSyns"`
	MaxConcurrentStreamsPerConnection int  `json:"maxConcurrentStreamsPerConnection"`
	MaxConcurrentConnections          int  `json:"maxConcurrentConnections"`
	SynFloodSignature                 struct {
		Enabled              bool    `json:"enabled"`
		WindowMs             int     `json:"windowMs"`
		MinSamples           int     `json:"minSamples"`
		FailedHandshakeRatio float64 `json:"failedHandshakeRatio"`
	} `json:"synFloodSignature"`
	WsCloseAfterViolations int  `json:"wsCloseAfterViolations"`
	LogBlockedDials        bool `json:"logBlockedDials"`
}

type ReputationConfig struct {
	Enabled      bool   `json:"enabled"`
	StorePath    string `json:"storePath"`
	DecayPerHour int    `json:"scoreDecayPerHour"`
	EvictAfter   time.Duration
	EvictDays    int            `json:"evictAfterDays"`
	Weights      map[string]int `json:"weights"`
	DestWeights  map[string]int `json:"destinationWeights"`
	Thresholds   struct {
		Warn     int `json:"warn"`
		Throttle int `json:"throttle"`
		Strict   int `json:"strict"`
	} `json:"thresholds"`
	SaveIntervalSeconds int `json:"saveIntervalSeconds"`
}

func validPortNumber(value float64) (uint16, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) || value < 1 || value > 65535 {
		return 0, fmt.Errorf("port must be an integer between 1 and 65535")
	}
	return uint16(value), nil
}

type SignatureConfig struct {
	Enabled              bool
	Window               time.Duration
	MinSamples           int
	FailedHandshakeRatio float64
}

type DNSCacheConfig struct {
	Servers     []string
	TTLSeconds  int
	Method      string
	ResultOrder string
}

func DefaultConfig() Config {
	return Config{
		Port: 6001,

		Blacklist: FilterSet{Hostnames: map[string]struct{}{}, Ports: map[uint16]struct{}{}},
		Whitelist: FilterSet{Hostnames: map[string]struct{}{}, Ports: map[uint16]struct{}{}},

		AllowTCP: true,
		AllowUDP: true,

		AllowDirectIP:    false,
		AllowPrivateIPs:  false,
		AllowLoopbackIPs: false,

		TcpBufferSize:    256 * 1024,
		TcpNoDelay:       true,
		SocketBufferSize: 16 * 1024 * 1024,
		PendingQueueSize: 64 * 1024 * 1024,

		DnsServers:     []string{},
		DnsMethod:      "resolve",
		DnsResultOrder: "ipv4first",

		EnableTwisp: false,

		EnableV2:                true,
		HandshakeTimeoutSeconds: 10,
		Motd:                    "",
		PasswordAuth:            false,
		PasswordAuthRequired:    false,
		PasswordUsers:           map[string]string{},

		ParseRealIP:    true,
		TrustedProxies: []string{},
		TrustedHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"},
		NonWSResponse:  "",

		LogLevel: "info",

		Proxy:                   "",
		MaxMessageSize:          0,
		StaticDir:               "",
		BandwidthLimitKbps:      0,
		ConnectionsLimitPerIP:   0,
		ConnectionWindowSeconds: 0,
		BufferRemainingLength:   32768,
	}
}

func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.TcpBufferSize < 1024 || cfg.TcpBufferSize > 16*1024*1024 {
		return fmt.Errorf("tcpBufferSize must be between 1024 and 16777216")
	}
	if cfg.SocketBufferSize < 64*1024 || cfg.SocketBufferSize > 256*1024*1024 {
		return fmt.Errorf("socketBufferSize must be between 65536 and 268435456")
	}
	if cfg.PendingQueueSize < cfg.TcpBufferSize || cfg.PendingQueueSize > 1024*1024*1024 {
		return fmt.Errorf("pendingQueueSize must be at least tcpBufferSize and at most 1073741824")
	}
	if cfg.WebsocketPermessageDeflate {
		return fmt.Errorf("websocketPermessageDeflate is incompatible with the zero-copy frame path")
	}
	if err := validateProxyURL(cfg.Proxy); err != nil {
		return err
	}
	if cfg.BufferRemainingLength == 0 {
		return fmt.Errorf("bufferRemainingLength must be greater than zero")
	}
	if cfg.MaxMessageSize < 0 {
		return fmt.Errorf("maxMessageSize cannot be negative")
	}
	if cfg.MaxMessageSize > 0 && cfg.MaxMessageSize < 5 {
		return fmt.Errorf("maxMessageSize must be zero or at least 5")
	}
	if cfg.MaxMessageSize > 1024*1024*1024 {
		return fmt.Errorf("maxMessageSize cannot exceed 1073741824")
	}
	if cfg.ConnectionsLimitPerIP < 0 || cfg.ConnectionWindowSeconds < 0 || cfg.BandwidthLimitKbps < 0 {
		return fmt.Errorf("connection and bandwidth limits cannot be negative")
	}
	if cfg.BandwidthLimitKbps > 1_000_000_000 {
		return fmt.Errorf("bandwidthLimitKbps cannot exceed 1000000000")
	}
	if (cfg.ConnectionsLimitPerIP == 0) != (cfg.ConnectionWindowSeconds == 0) {
		return fmt.Errorf("connectionsLimitPerIP and connectionWindowSeconds must both be set or both be zero")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DnsMethod)) {
	case "lookup", "resolve":
	default:
		return fmt.Errorf("dnsMethod must be lookup or resolve")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DnsResultOrder)) {
	case "ipv4first", "ipv6first", "verbatim":
	default:
		return fmt.Errorf("dnsResultOrder must be ipv4first, ipv6first, or verbatim")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.LogLevel)) {
	case "debug", "info", "warn", "error", "none":
	default:
		return fmt.Errorf("logLevel must be debug, info, warn, error, or none")
	}
	for _, entry := range cfg.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if net.ParseIP(entry) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return fmt.Errorf("trustedProxies entry %q is not an IP address or CIDR", entry)
		}
	}
	for _, header := range cfg.TrustedHeaders {
		if !validHTTPHeaderName(header) {
			return fmt.Errorf("trustedHeaders entry %q is not a valid HTTP header name", header)
		}
	}
	if cfg.PasswordAuthRequired && !cfg.PasswordAuth {
		return fmt.Errorf("passwordAuthRequired requires passwordAuth")
	}
	if cfg.PasswordAuthRequired && len(cfg.PasswordUsers) == 0 {
		return fmt.Errorf("passwordAuthRequired requires at least one passwordUsers entry")
	}
	if cfg.HandshakeTimeoutSeconds < 1 || cfg.HandshakeTimeoutSeconds > 300 {
		return fmt.Errorf("handshakeTimeoutSeconds must be between 1 and 300")
	}
	if cfg.FloodProtection != nil {
		fp := cfg.FloodProtection
		limits := []struct {
			name  string
			value int
		}{
			{"maxConnectsPerSourceIPPerSecond", fp.MaxConnectsPerSourceIPPerSecond},
			{"maxConnectsPerDestPerSecond", fp.MaxConnectsPerDestPerSecond},
			{"maxConnectsPerDestPerMinute", fp.MaxConnectsPerDestPerMinute},
			{"maxInFlightSyns", fp.MaxInFlightSyns},
			{"maxConcurrentStreamsPerConnection", fp.MaxConcurrentStreamsPerConnection},
			{"maxConcurrentConnections", fp.MaxConcurrentConnections},
			{"wsCloseAfterViolations", fp.WsCloseAfterViolations},
		}
		for _, limit := range limits {
			if limit.value < 0 {
				return fmt.Errorf("floodProtection.%s cannot be negative", limit.name)
			}
		}
		s := cfg.FloodProtection.SynFloodSignature
		if s.FailedHandshakeRatio < 0 || s.FailedHandshakeRatio > 1 {
			return fmt.Errorf("synFloodSignature.failedHandshakeRatio must be between 0 and 1")
		}
		if s.Enabled && (s.WindowMs <= 0 || s.MinSamples <= 0 || s.FailedHandshakeRatio <= 0) {
			return fmt.Errorf("enabled synFloodSignature requires positive windowMs, minSamples, and failedHandshakeRatio")
		}
	}
	return nil
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func CreateWispConfig(cfg *Config) *Config {
	if cfg == nil {
		defaults := DefaultConfig()
		cfg = &defaults
	}
	clone := *cfg
	clone.Blacklist = FilterSet{
		Hostnames: maps.Clone(cfg.Blacklist.Hostnames),
		Ports:     maps.Clone(cfg.Blacklist.Ports),
	}
	clone.Whitelist = FilterSet{
		Hostnames: maps.Clone(cfg.Whitelist.Hostnames),
		Ports:     maps.Clone(cfg.Whitelist.Ports),
	}
	clone.DnsServers = append([]string(nil), cfg.DnsServers...)
	clone.PasswordUsers = maps.Clone(cfg.PasswordUsers)
	clone.TrustedProxies = append([]string(nil), cfg.TrustedProxies...)
	clone.TrustedHeaders = append([]string(nil), cfg.TrustedHeaders...)
	if cfg.FloodProtection != nil {
		flood := *cfg.FloodProtection
		clone.FloodProtection = &flood
	}
	if cfg.Reputation != nil {
		reputation := *cfg.Reputation
		reputation.Weights = maps.Clone(cfg.Reputation.Weights)
		reputation.DestWeights = maps.Clone(cfg.Reputation.DestWeights)
		clone.Reputation = &reputation
	}
	clone.trustedProxyNets = nil
	clone.Logger = nil
	clone.DNSCache = nil
	clone.ReadBufPool = nil
	clone.Dialer = net.Dialer{}
	clone.Globals = nil
	return &clone
}

func LoadConfig(config string) (Config, error) {
	cfg := DefaultConfig()

	trimConfig := strings.TrimSpace(config)
	if strings.HasPrefix(trimConfig, "{") {
		if err := decodeConfig(strings.NewReader(trimConfig), &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	file, err := os.Open(config)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	if err := decodeConfig(file, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func decodeConfig(reader io.Reader, cfg *Config) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("config contains multiple JSON values")
		}
		return fmt.Errorf("invalid trailing config data: %w", err)
	}
	return nil
}
