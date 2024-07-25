package eth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/prysm/v5/api/server/structs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/probe-lab/hermes/tele"
)

func TestPrysmClient_AddTrustedPeer(t *testing.T) {
	otel.SetTracerProvider(tele.NoopTracerProvider())

	maddr, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1234")
	require.NoError(t, err)

	pid, err := peer.Decode("16Uiu2HAmBBTgCRezbBY8LbdfDN5PXYi3C1hwdoXJ9DZAorsWs4NR")
	require.NoError(t, err)

	tests := []struct {
		name           string
		respStatusCode int
		respBody       string
		expectErr      bool
	}{
		{
			name:           "success",
			respStatusCode: http.StatusOK,
			respBody:       "",
			expectErr:      false,
		},
		{
			name:           "error_json_unmarshal",
			respStatusCode: http.StatusBadRequest,
			respBody:       "{invalid_json}",
			expectErr:      true,
		},
		{
			name:           "invalid_response_status_code",
			respStatusCode: http.StatusBadRequest,
			respBody:       `{"message": "internal error"}`,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/prysm/node/trusted_peers", r.URL.Path)

				data, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				defer assert.NoError(t, r.Body.Close())

				reqData := &structs.AddrRequest{}
				err = json.Unmarshal(data, reqData)
				require.NoError(t, err)

				assert.Equal(t, maddr.String()+"/p2p/"+pid.String(), reqData.Addr)

				w.WriteHeader(tt.respStatusCode)
				_, _ = fmt.Fprintln(w, tt.respBody)
			}))
			defer server.Close()

			// Get mocked server URL
			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)

			port, err := strconv.Atoi(serverURL.Port())
			require.NoError(t, err)

			p, err := NewPrysmClient(serverURL.Hostname(), port, 0, time.Second, nil)
			require.NoError(t, err)

			err = p.AddTrustedPeer(context.Background(), pid, maddr)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrysmClient_RemoveTrustedPeer(t *testing.T) {
	otel.SetTracerProvider(tele.NoopTracerProvider())

	pid, err := peer.Decode("16Uiu2HAmBBTgCRezbBY8LbdfDN5PXYi3C1hwdoXJ9DZAorsWs4NR")
	require.NoError(t, err)

	tests := []struct {
		name           string
		respStatusCode int
		respBody       string
		expectErr      bool
	}{
		{
			name:           "success",
			respStatusCode: http.StatusOK,
			respBody:       "",
			expectErr:      false,
		},
		{
			name:           "error_json_unmarshal",
			respStatusCode: http.StatusBadRequest,
			respBody:       "{invalid_json}",
			expectErr:      true,
		},
		{
			name:           "invalid_response_status_code",
			respStatusCode: http.StatusBadRequest,
			respBody:       `{"message": "internal error"}`,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock HTTP server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodDelete, r.Method)
				assert.Equal(t, "/prysm/node/trusted_peers/"+pid.String(), r.URL.Path)

				w.WriteHeader(tt.respStatusCode)
				_, _ = fmt.Fprintln(w, tt.respBody)
			}))
			defer server.Close()

			// Get mocked server URL
			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)

			port, err := strconv.Atoi(serverURL.Port())
			require.NoError(t, err)

			p, err := NewPrysmClient(serverURL.Hostname(), port, 0, time.Second, nil)
			require.NoError(t, err)

			err = p.RemoveTrustedPeer(context.Background(), pid)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
