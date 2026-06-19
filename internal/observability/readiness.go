package observability

import "sync/atomic"

// ReadinessProbe is a thread-safe probe that tracks whether the application is ready
// to serve traffic. It starts in a not-ready state.
type ReadinessProbe struct {
	ready atomic.Bool
}

// NewReadinessProbe creates a new ReadinessProbe in the not-ready state.
func NewReadinessProbe() *ReadinessProbe {
	return &ReadinessProbe{}
}

// MarkReady signals that the application is ready to serve traffic.
func (p *ReadinessProbe) MarkReady() {
	p.ready.Store(true)
}

// MarkNotReady signals that the application is no longer ready to serve traffic.
func (p *ReadinessProbe) MarkNotReady() {
	p.ready.Store(false)
}

// IsReady returns true if the application is ready to serve traffic.
func (p *ReadinessProbe) IsReady() bool {
	return p.ready.Load()
}
