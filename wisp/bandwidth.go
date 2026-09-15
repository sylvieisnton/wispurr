package wisp

import (
	"sync"
	"time"
)

type BandwidthLimiter struct {
	bytesPerSecond float64
	burst          time.Duration

	mutex      sync.Mutex
	buckets map[string]bandwidthBucket
}

type bandwidthBucket struct {
	next     time.Time
	lastSeen time.Time
}

func NewBandwidthLimiter(bytesPerSecond int64) *BandwidthLimiter {
	if bytesPerSecond <= 0 {
		return nil
	}
	return &BandwidthLimiter{
		bytesPerSecond: float64(bytesPerSecond),
		burst:          time.Second,
		buckets:        make(map[string]bandwidthBucket),
	}
}

func (l *BandwidthLimiter) Wait(stop <-chan struct{}, key string, size int) bool {
	if l == nil || size <= 0 {
		return true
	}

	now := time.Now()
	cost := time.Duration(float64(size) / l.bytesPerSecond * float64(time.Second))
	if cost <= 0 {
		return true
	}

	l.mutex.Lock()
	bucket := l.buckets[key]
	earliest := now.Add(-l.burst)
	start := bucket.next
	if start.Before(earliest) {
		start = earliest
	}
	finish := start.Add(cost)
	bucket.next = finish
	bucket.lastSeen = now
	l.buckets[key] = bucket
	l.mutex.Unlock()

	delay := time.Until(finish)
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	}
}

func (l *BandwidthLimiter) Evict(idle time.Duration) {
	if l == nil {
		return
	}
	cutoff := time.Now().Add(-idle)
	l.mutex.Lock()
	for key, bucket := range l.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
	l.mutex.Unlock()
}
