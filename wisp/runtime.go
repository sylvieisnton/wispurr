package wisp

import (
	"sync"
	"sync/atomic"
	"time"
)

type Globals struct {
	PerSource      *SlidingWindow
	ConnectionRate *SlidingWindow
	Bandwidth      *BandwidthLimiter
	PerDestSec     *SlidingWindow
	PerDestMin     *SlidingWindow
	InFlightSyns   *Semaphore
	Connections    *Semaphore
	Egress         *EgressPolicy
	Reputation     *Reputation
	Signature      *Signatures

	active            sync.Map
	stop              chan struct{}
	stopOnce          sync.Once
	startedAt         time.Time
	totalIngressBytes atomic.Uint64
	totalEgressBytes  atomic.Uint64
}

type ServerStats struct {
	UptimeSeconds     float64 `json:"uptimeSeconds"`
	ActiveConnections int64   `json:"activeConnections"`
	ActiveStreams     int64   `json:"activeStreams"`
	IngressBytes      uint64  `json:"ingressBytes"`
	EgressBytes       uint64  `json:"egressBytes"`
}

func (cfg *Config) BuildGlobals() {
	if cfg.Globals != nil {
		return
	}
	g := &Globals{Egress: PolicyFromConfig(cfg), stop: make(chan struct{}), startedAt: time.Now()}
	if cfg.ConnectionsLimitPerIP > 0 && cfg.ConnectionWindowSeconds > 0 {
		g.ConnectionRate = NewSlidingWindow(cfg.ConnectionsLimitPerIP, time.Duration(cfg.ConnectionWindowSeconds)*time.Second)
	}
	if cfg.BandwidthLimitKbps > 0 {
		g.Bandwidth = NewBandwidthLimiter(int64(cfg.BandwidthLimitKbps) * 1000 / 8)
	}
	if cfg.FloodProtection != nil && cfg.FloodProtection.Enabled {
		fp := cfg.FloodProtection
		if fp.MaxConnectsPerSourceIPPerSecond > 0 {
			g.PerSource = NewSlidingWindow(fp.MaxConnectsPerSourceIPPerSecond, time.Second)
		}
		if fp.MaxConnectsPerDestPerSecond > 0 {
			g.PerDestSec = NewSlidingWindow(fp.MaxConnectsPerDestPerSecond, time.Second)
		}
		if fp.MaxConnectsPerDestPerMinute > 0 {
			g.PerDestMin = NewSlidingWindow(fp.MaxConnectsPerDestPerMinute, time.Minute)
		}
		if fp.MaxInFlightSyns > 0 {
			g.InFlightSyns = NewSemaphore(fp.MaxInFlightSyns)
		}
		if fp.MaxConcurrentConnections > 0 {
			g.Connections = NewSemaphore(fp.MaxConcurrentConnections)
		}
		g.Signature = NewSignatures(SignatureConfig{
			Enabled:              fp.SynFloodSignature.Enabled,
			Window:               time.Duration(fp.SynFloodSignature.WindowMs) * time.Millisecond,
			MinSamples:           fp.SynFloodSignature.MinSamples,
			FailedHandshakeRatio: fp.SynFloodSignature.FailedHandshakeRatio,
		})
	}
	if cfg.Reputation != nil && cfg.Reputation.Enabled {
		rc := *cfg.Reputation
		if rc.EvictAfter == 0 && rc.EvictDays > 0 {
			rc.EvictAfter = time.Duration(rc.EvictDays) * 24 * time.Hour
		}
		g.Reputation = NewReputation(rc)
		if err := g.Reputation.Load(); err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Warn("reputation load failed", "error", err)
			}
		}
		saveEvery := time.Duration(rc.SaveIntervalSeconds) * time.Second
		if saveEvery <= 0 {
			saveEvery = 30 * time.Second
		}
		go g.Reputation.RunMaintenance(g.stop, saveEvery)
	}
	if g.PerSource != nil || g.ConnectionRate != nil || g.Bandwidth != nil || g.PerDestSec != nil || g.PerDestMin != nil {
		go g.runMaintenance()
	}
	cfg.Globals = g
}

func (cfg *Config) Stats() ServerStats {
	var stats ServerStats
	if cfg == nil || cfg.Globals == nil {
		return stats
	}
	g := cfg.Globals
	stats.UptimeSeconds = time.Since(g.startedAt).Seconds()
	stats.IngressBytes = g.totalIngressBytes.Load()
	stats.EgressBytes = g.totalEgressBytes.Load()
	g.active.Range(func(_, value any) bool {
		if c, ok := value.(*wispConnection); ok {
			stats.ActiveConnections++
			stats.ActiveStreams += int64(c.streamCount.Load())
			stats.IngressBytes += c.ingressBytes.Load()
			stats.EgressBytes += c.egressBytes.Load()
		}
		return true
	})
	return stats
}

func (g *Globals) runMaintenance() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if g.PerSource != nil {
				g.PerSource.Evict(2 * time.Minute)
			}
			if g.ConnectionRate != nil {
				g.ConnectionRate.Evict(2 * g.ConnectionRate.window)
			}
			if g.Bandwidth != nil {
				g.Bandwidth.Evict(10 * time.Minute)
			}
			if g.PerDestSec != nil {
				g.PerDestSec.Evict(2 * time.Minute)
			}
			if g.PerDestMin != nil {
				g.PerDestMin.Evict(2 * time.Hour)
			}
		case <-g.stop:
			return
		}
	}
}

func (cfg *Config) Shutdown() {
	if cfg == nil {
		return
	}
	if cfg.DNSCache != nil {
		cfg.DNSCache.Close()
	}
	if cfg.Globals == nil {
		return
	}
	g := cfg.Globals
	g.stopOnce.Do(func() { close(g.stop) })
	g.active.Range(func(_, value any) bool {
		if c, ok := value.(*wispConnection); ok {
			c.close()
		}
		return true
	})
}
