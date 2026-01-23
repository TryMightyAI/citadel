package ml

import (
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// OSS IN-MEMORY SESSION STORE
// ============================================================================
// Thread-safe in-memory session storage with TTL-based cleanup.
// Implements MTSessionStore interface for the OSS multi-turn detector.
//
// Features:
//   - Concurrent-safe session access
//   - Automatic TTL expiration (default: 1 hour)
//   - Sliding window message trimming
//   - Cross-window pattern signal persistence

// MTInMemoryStore implements MTSessionStore with in-memory storage.
// Suitable for single-node deployments. For distributed deployments,
// Pro provides Redis-backed session storage.
type MTInMemoryStore struct {
	sessions map[string]*SessionState
	mu       sync.RWMutex

	// Configuration
	maxAge     time.Duration // Session TTL (default: 1 hour)
	cleanupTTL time.Duration // Cleanup interval (default: 5 minutes)

	// Cleanup goroutine control
	stopCleanup chan struct{}
	cleanupOnce sync.Once
}

// MTStoreOption is a functional option for configuring MTInMemoryStore.
type MTStoreOption func(*MTInMemoryStore)

// WithMaxAge sets the maximum age for sessions before cleanup.
func WithMaxAge(d time.Duration) MTStoreOption {
	return func(s *MTInMemoryStore) {
		s.maxAge = d
	}
}

// WithCleanupInterval sets how often the cleanup routine runs.
func WithCleanupInterval(d time.Duration) MTStoreOption {
	return func(s *MTInMemoryStore) {
		s.cleanupTTL = d
	}
}

// NewMTInMemoryStore creates a new in-memory session store.
func NewMTInMemoryStore(opts ...MTStoreOption) *MTInMemoryStore {
	s := &MTInMemoryStore{
		sessions:    make(map[string]*SessionState),
		maxAge:      1 * time.Hour,
		cleanupTTL:  5 * time.Minute,
		stopCleanup: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Start background cleanup
	go s.cleanupLoop()

	return s
}

// Get retrieves a session by ID. Returns nil, nil if not found.
func (s *MTInMemoryStore) Get(sessionID string) (*SessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil // Not found is not an error
	}

	// Check if session is expired
	if time.Since(session.LastTurnAt) > s.maxAge {
		// Session is stale, treat as not found
		// Actual cleanup happens in cleanupLoop
		return nil, nil
	}

	return session, nil
}

// Save creates or updates a session.
func (s *MTInMemoryStore) Save(state *SessionState) error {
	if state == nil {
		return fmt.Errorf("session state is nil")
	}
	if state.SessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Initialize timestamps if not set
	if state.CreatedAt.IsZero() {
		state.CreatedAt = time.Now()
	}
	if state.LastTurnAt.IsZero() {
		state.LastTurnAt = time.Now()
	}

	// Initialize defaults
	if state.MaxMessages == 0 {
		state.MaxMessages = 15 // OSS default
	}
	if state.PatternSignals == nil {
		state.PatternSignals = make(map[string]*StoredPatternSignal)
	}

	s.sessions[state.SessionID] = state
	return nil
}

// UpdateTurn appends a turn record to an existing session.
func (s *MTInMemoryStore) UpdateTurn(sessionID string, turn *MTTurnRecord) error {
	if turn == nil {
		return fmt.Errorf("turn record is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Set timestamp if not set
	if turn.Timestamp.IsZero() {
		turn.Timestamp = time.Now()
	}

	// Append turn
	session.Messages = append(session.Messages, *turn)

	// Trim to max messages (sliding window)
	if len(session.Messages) > session.MaxMessages {
		session.Messages = session.Messages[len(session.Messages)-session.MaxMessages:]
	}

	// Update session metadata
	session.LastTurnAt = turn.Timestamp
	session.TurnCount++

	return nil
}

// Delete removes a session.
func (s *MTInMemoryStore) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

// Close stops the cleanup goroutine.
func (s *MTInMemoryStore) Close() {
	s.cleanupOnce.Do(func() {
		close(s.stopCleanup)
	})
}

// cleanupLoop periodically removes expired sessions.
func (s *MTInMemoryStore) cleanupLoop() {
	ticker := time.NewTicker(s.cleanupTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopCleanup:
			return
		}
	}
}

// cleanup removes expired sessions.
func (s *MTInMemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.LastTurnAt) > s.maxAge {
			delete(s.sessions, id)
		}
	}
}

// Stats returns current session store statistics.
func (s *MTInMemoryStore) Stats() MTStoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := MTStoreStats{
		SessionCount: len(s.sessions),
	}

	for _, session := range s.sessions {
		stats.TotalTurns += session.TurnCount
		stats.TotalMessages += len(session.Messages)
	}

	return stats
}

// MTStoreStats contains session store statistics.
type MTStoreStats struct {
	SessionCount  int `json:"session_count"`
	TotalTurns    int `json:"total_turns"`
	TotalMessages int `json:"total_messages"` // In-memory message count
}

// Ensure MTInMemoryStore implements MTSessionStore
var _ MTSessionStore = (*MTInMemoryStore)(nil)
