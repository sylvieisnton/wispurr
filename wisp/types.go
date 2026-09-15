package wisp

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxzan/gws"
	"golang.org/x/sync/singleflight"
)

// logger

type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

type Log struct {
	level int
	inner *log.Logger
}

// dnscache

type dnsEntry struct {
	ips       []net.IPAddr
	expiresAt time.Time
	err       error
}

type DNSCache struct {
	servers     []string
	resolver    *net.Resolver
	ttl         time.Duration
	resultOrder string

	mu    sync.RWMutex
	cache map[string]dnsEntry
	group singleflight.Group
	stop  chan struct{}
	once  sync.Once
}

// egress

type EgressPolicy struct {
	AllowLoopback bool
	AllowPrivate  bool

	AllowIPs   map[string]struct{}
	AllowCIDRs []*net.IPNet
	DenyIPs    map[string]struct{}
	DenyCIDRs  []*net.IPNet
}

// limits

type SlidingWindow struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	entries map[string]*windowEntry
}

type windowEntry struct {
	start time.Time
	count int
}

type Semaphore struct {
	max     int64
	current int64
}

// reputation

type SourceEntry struct {
	Score     int            `json:"score"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	Events    map[string]int `json:"events"`
}

type DestEntry struct {
	Score           int             `json:"score"`
	FirstSeen       time.Time       `json:"firstSeen"`
	LastSeen        time.Time       `json:"lastSeen"`
	Events          map[string]int  `json:"events"`
	DistinctSources int             `json:"distinctSources"`
	SeenSources     map[string]bool `json:"seenSources"`
}

type Reputation struct {
	cfg       ReputationConfig
	mu        sync.RWMutex
	sources   map[string]*SourceEntry
	dests     map[string]*DestEntry
	lastDecay time.Time
}

type repSnapshot struct {
	Sources map[string]*SourceEntry `json:"sources"`
	Dests   map[string]*DestEntry   `json:"destinations"`
}

// signature

type Signatures struct {
	cfg SignatureConfig
	mu  sync.Mutex
	per map[string]*Detector
}

type sample struct {
	t  time.Time
	ok bool
}

type Detector struct {
	cfg  SignatureConfig
	mu   sync.Mutex
	ring []sample
}

// v2

type Extensions struct {
	udp           bool
	streamConfirm bool

	passwordUsername string
	passwordPassword string

	certificateUsername   string
	certificateSelected   uint8
	certificatePubkeyHash [32]byte
	certificateSig        []byte
}

// wisp connection

type writeReq struct {
	data []byte
	buf  *[]byte
	done chan error
}

type wispConnection struct {
	netConn      net.Conn
	streams      sync.Map
	isClosed     atomic.Bool
	shutdownOnce sync.Once
	config       *Config
	twispStreams *twispRegistry
	remoteIP     string

	streamCache [streamCacheSize]atomic.Pointer[wispStream]

	pendingMutex  sync.Mutex
	pendingWrites []writeReq
	pendingBytes  int
	writeActive   bool

	isV2          bool
	handshakeDone chan struct{}
	streamConfirm bool
	v2Challenge   []byte
	authenticated atomic.Bool

	dialSem     chan struct{}
	closeCh     chan struct{}
	createdAt   time.Time
	streamCount atomic.Int32

	globals      *Globals
	connID       uint64
	violations   atomic.Int32
	ingressBytes atomic.Uint64
	egressBytes  atomic.Uint64
}

// wisp stream

type wispStream struct {
	wispConn *wispConnection

	streamId        uint32
	streamType      uint8
	conn            net.Conn
	bufferRemaining uint32
	hostname        string
	portNum         int

	connReady     chan struct{}
	connReadyDone atomic.Bool

	isOpen atomic.Bool

	pendingMutex sync.Mutex
	pendingData  [][]byte
	pendingBytes int

	ingressActive   atomic.Bool
	pendingIngMu    sync.Mutex
	pendingIngress  []ingressJob
	pendingIngBytes int
	ingressWriting  bool
}

type ingressJob struct {
	payload []byte
	bufp    *[]byte
	pool    ingressPool
}

type ingressPool uint8

// wisp

type upgradeHandler struct {
	gws.BuiltinEventHandler
}
