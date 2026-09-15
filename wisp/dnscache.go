package wisp

import (
	"context"
	"net"
	"strings"
	"time"
)

func NewDNSCache(cfg DNSCacheConfig) *DNSCache {
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	cache := &DNSCache{
		servers:     cfg.Servers,
		ttl:         ttl,
		resultOrder: cfg.ResultOrder,
		cache:       make(map[string]dnsEntry),
		stop:        make(chan struct{}),
	}
	cache.initResolver(cfg.Method)
	cache.cleanup()
	return cache
}

func (d *DNSCache) cleanup() {
	interval := d.ttl / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.expire()
			case <-d.stop:
				return
			}
		}
	}()
}

func (d *DNSCache) Close() {
	if d != nil {
		d.once.Do(func() { close(d.stop) })
	}
}

func (d *DNSCache) expire() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for host, entry := range d.cache {
		if now.After(entry.expiresAt) {
			delete(d.cache, host)
		}
	}
}

func (d *DNSCache) initResolver(method string) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "resolve" && len(d.servers) > 0 {
		server := firstDNSServer(d.servers)
		if server == "" {
			d.resolver = net.DefaultResolver
			return
		}
		d.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: 5 * time.Second,
				}
				return dialer.DialContext(ctx, "udp", server)
			},
		}
		return
	}
	d.resolver = net.DefaultResolver
}

func firstDNSServer(servers []string) string {
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		return normalizeDNSServer(server)
	}
	return ""
}

func normalizeDNSServer(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

func (d *DNSCache) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = NormalizeTargetHostname(host)
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	now := time.Now()

	d.mu.RLock()
	entry, ok := d.cache[host]
	d.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.ips, nil
	}

	v, err, _ := d.group.Do(host, func() (any, error) {
		ips, resolveErr := d.resolver.LookupIPAddr(ctx, host)
		if resolveErr == nil {
			ips = reorderIPs(ips, d.resultOrder)
		}
		entry := dnsEntry{
			ips:       ips,
			expiresAt: time.Now().Add(d.ttl),
			err:       resolveErr,
		}
		d.mu.Lock()
		d.cache[host] = entry
		d.mu.Unlock()
		return entry, resolveErr
	})
	if err != nil {
		return nil, err
	}
	entry, ok = v.(dnsEntry)
	if !ok {
		return nil, err
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.ips, nil
}

func reorderIPs(ips []net.IPAddr, order string) []net.IPAddr {
	if len(ips) <= 1 {
		return ips
	}
	order = strings.ToLower(strings.TrimSpace(order))
	if order == "verbatim" || order == "" {
		return ips
	}

	var v4 []net.IPAddr
	var v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}

	if order == "ipv4first" {
		return append(v4, v6...)
	}
	if order == "ipv6first" {
		return append(v6, v4...)
	}

	return ips
}
