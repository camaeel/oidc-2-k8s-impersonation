package observability

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	testcases := []struct {
		name       string
		path       string
		ready      bool
		wantStatus int
		wantBody   statusResponse
	}{
		{
			name:       "/livez always returns 200",
			path:       "/livez",
			ready:      false,
			wantStatus: http.StatusOK,
			wantBody:   statusResponse{Status: "ok"},
		},
		{
			name:       "/livez returns 200 when ready",
			path:       "/livez",
			ready:      true,
			wantStatus: http.StatusOK,
			wantBody:   statusResponse{Status: "ok"},
		},
		{
			name:       "/readyz returns 503 when not ready",
			path:       "/readyz",
			ready:      false,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   statusResponse{Status: "not_ready"},
		},
		{
			name:       "/readyz returns 200 when ready",
			path:       "/readyz",
			ready:      true,
			wantStatus: http.StatusOK,
			wantBody:   statusResponse{Status: "ok"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			probe := NewReadinessProbe()
			if tc.ready {
				probe.MarkReady()
			}

			handler := NewHandler(probe)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var body statusResponse
			err := json.NewDecoder(rec.Body).Decode(&body)
			require.NoError(t, err)
			assert.Equal(t, tc.wantBody, body)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		})
	}
}
