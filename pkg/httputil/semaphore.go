package httputil

import (
	"context"
	"sync/atomic"
)

// Semaphore limits concurrent operations to prevent goroutine explosion.
// Use this for fire-and-forget operations that could accumulate.
type Semaphore struct {
	sem     chan struct{}
	dropped atomic.Int64
}

// NewSemaphore creates a semaphore with the given capacity.
// Capacity should be set based on expected load and resource constraints.
func NewSemaphore(capacity int) *Semaphore {
	if capacity <= 0 {
		capacity = 100
	}
	return &Semaphore{
		sem: make(chan struct{}, capacity),
	}
}

// TryAcquire attempts to acquire a semaphore slot without blocking.
// Returns true if acquired, false if at capacity.
// Use this for fire-and-forget operations where dropping is acceptable.
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

// Acquire blocks until a slot is available or context is cancelled.
// Use this when the operation must eventually complete.
func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot to the semaphore.
// Must be called after successful TryAcquire() or Acquire().
func (s *Semaphore) Release() {
	select {
	case <-s.sem:
	default:
		// Shouldn't happen - releasing without acquiring
	}
}

// DroppedCount returns the number of operations dropped due to capacity.
// Useful for monitoring backpressure.
func (s *Semaphore) DroppedCount() int64 {
	return s.dropped.Load()
}

// Available returns the number of available slots.
func (s *Semaphore) Available() int {
	return cap(s.sem) - len(s.sem)
}

// InUse returns the number of slots currently in use.
func (s *Semaphore) InUse() int {
	return len(s.sem)
}

// Stats returns current semaphore statistics.
func (s *Semaphore) Stats() SemaphoreStats {
	return SemaphoreStats{
		Capacity:  cap(s.sem),
		InUse:     len(s.sem),
		Available: cap(s.sem) - len(s.sem),
		Dropped:   s.dropped.Load(),
	}
}

// SemaphoreStats provides semaphore metrics for monitoring.
type SemaphoreStats struct {
	Capacity  int   `json:"capacity"`
	InUse     int   `json:"in_use"`
	Available int   `json:"available"`
	Dropped   int64 `json:"dropped"`
}
