package httputil

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSemaphore_TryAcquire(t *testing.T) {
	sem := NewSemaphore(2)

	// First two should succeed
	if !sem.TryAcquire() {
		t.Error("First TryAcquire should succeed")
	}
	if !sem.TryAcquire() {
		t.Error("Second TryAcquire should succeed")
	}

	// Third should fail (at capacity)
	if sem.TryAcquire() {
		t.Error("Third TryAcquire should fail (at capacity)")
	}

	// Verify dropped count
	if sem.DroppedCount() != 1 {
		t.Errorf("DroppedCount = %d, want 1", sem.DroppedCount())
	}

	// Release one and try again
	sem.Release()
	if !sem.TryAcquire() {
		t.Error("TryAcquire should succeed after Release")
	}
}

func TestSemaphore_Acquire(t *testing.T) {
	sem := NewSemaphore(1)

	// First should succeed immediately
	ctx := context.Background()
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("First Acquire failed: %v", err)
	}

	// Second should block and timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := sem.Acquire(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded, got %v", err)
	}
}

func TestSemaphore_Concurrent(t *testing.T) {
	sem := NewSemaphore(10)
	var acquired atomic.Int32
	var wg sync.WaitGroup

	// Try to acquire 100 times concurrently
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem.TryAcquire() {
				acquired.Add(1)
				time.Sleep(10 * time.Millisecond)
				sem.Release()
			}
		}()
	}

	wg.Wait()

	// Should have acquired some but not all simultaneously
	stats := sem.Stats()
	t.Logf("Concurrent test: acquired=%d, dropped=%d", acquired.Load(), stats.Dropped)

	// All should be released now
	if stats.InUse != 0 {
		t.Errorf("Expected 0 in use after completion, got %d", stats.InUse)
	}
}

func TestSemaphore_Stats(t *testing.T) {
	sem := NewSemaphore(5)

	stats := sem.Stats()
	if stats.Capacity != 5 {
		t.Errorf("Capacity = %d, want 5", stats.Capacity)
	}
	if stats.Available != 5 {
		t.Errorf("Available = %d, want 5", stats.Available)
	}
	if stats.InUse != 0 {
		t.Errorf("InUse = %d, want 0", stats.InUse)
	}

	sem.TryAcquire()
	sem.TryAcquire()

	stats = sem.Stats()
	if stats.InUse != 2 {
		t.Errorf("InUse = %d, want 2", stats.InUse)
	}
	if stats.Available != 3 {
		t.Errorf("Available = %d, want 3", stats.Available)
	}
}

func TestNewSemaphore_DefaultCapacity(t *testing.T) {
	// Zero or negative should default to 100
	sem := NewSemaphore(0)
	if cap(sem.sem) != 100 {
		t.Errorf("Default capacity should be 100, got %d", cap(sem.sem))
	}

	sem = NewSemaphore(-5)
	if cap(sem.sem) != 100 {
		t.Errorf("Negative capacity should default to 100, got %d", cap(sem.sem))
	}
}

// BenchmarkSemaphore_TryAcquire benchmarks the non-blocking acquire.
func BenchmarkSemaphore_TryAcquire(b *testing.B) {
	sem := NewSemaphore(1000)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if sem.TryAcquire() {
				sem.Release()
			}
		}
	})
}
