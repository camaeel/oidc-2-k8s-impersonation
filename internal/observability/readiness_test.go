package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadinessProbe(t *testing.T) {
	testcases := []struct {
		name      string
		action    func(p *ReadinessProbe)
		wantReady bool
	}{
		{
			name:      "starts not ready",
			action:    func(p *ReadinessProbe) {},
			wantReady: false,
		},
		{
			name: "ready after MarkReady",
			action: func(p *ReadinessProbe) {
				p.MarkReady()
			},
			wantReady: true,
		},
		{
			name: "not ready after MarkNotReady",
			action: func(p *ReadinessProbe) {
				p.MarkReady()
				p.MarkNotReady()
			},
			wantReady: false,
		},
		{
			name: "ready again after re-marking ready",
			action: func(p *ReadinessProbe) {
				p.MarkReady()
				p.MarkNotReady()
				p.MarkReady()
			},
			wantReady: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			probe := NewReadinessProbe()
			tc.action(probe)
			assert.Equal(t, tc.wantReady, probe.IsReady())
		})
	}
}
