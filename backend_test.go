package aap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// getTestBackend returns a fresh backend wired to in-memory storage.
func getTestBackend(tb testing.TB) (*aapBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	require.NoError(tb, err)

	return b.(*aapBackend), config.StorageView
}

// mockAAP is an in-process stand-in for the AAP token API used by unit tests.
type mockAAP struct {
	mu        sync.Mutex
	nextID    int64
	live      map[int64]string // id -> scope, for tokens that still exist
	revoked   map[int64]bool   // ids that received a DELETE
	created   int              // count of successful mints
	wantAuth  string           // expected bearer token
	users     map[string]int64 // username -> id, for ResolveUserID lookups
	mintUsers map[int64]int64  // token id -> "user" field sent at mint (0 if none)
}

func newMockAAP(bearer string) *mockAAP {
	return &mockAAP{
		nextID:   100,
		live:     map[int64]string{},
		revoked:  map[int64]bool{},
		wantAuth: bearer,
		// Service accounts a per-user role can target in tests.
		users:     map[string]int64{"svc-deploy": 7, "svc-readonly": 8},
		mintUsers: map[int64]int64{},
	}
}

// server starts a TLS test server and returns it; callers must Close it.
func (m *mockAAP) server(tb testing.TB) *httptest.Server {
	tb.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/gateway/v1/tokens/", m.handleTokens)
	mux.HandleFunc("/api/gateway/v1/users/", m.handleUsers)
	return httptest.NewTLSServer(mux)
}

// handleUsers serves the ?username= lookup ResolveUserID performs.
func (m *mockAAP) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+m.wantAuth {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	username := r.URL.Query().Get("username")
	results := []map[string]interface{}{}
	if id, ok := m.users[username]; ok {
		results = append(results, map[string]interface{}{"id": id, "username": username})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(results), "results": results,
	})
}

// mintUserFor reports the "user" field the engine sent when minting a token id.
func (m *mockAAP) mintUserFor(id int64) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mintUsers[id]
}

func (m *mockAAP) handleTokens(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+m.wantAuth {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	suffix := strings.TrimPrefix(r.URL.Path, "/api/gateway/v1/tokens/")

	m.mu.Lock()
	defer m.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && suffix == "":
		// Connection verification (VerifyToken) lists the tokens collection.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})

	case r.Method == http.MethodPost && suffix == "":
		var body struct {
			Scope       string `json:"scope"`
			Description string `json:"description"`
			User        int64  `json:"user"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := m.nextID
		m.nextID++
		m.live[id] = body.Scope
		m.mintUsers[id] = body.User
		m.created++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          id,
			"token":       "secret-token-" + strconv.FormatInt(id, 10),
			"scope":       body.Scope,
			"description": body.Description,
			"expires":     time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		})

	case r.Method == http.MethodDelete && suffix != "":
		idStr := strings.TrimSuffix(suffix, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"detail":"bad id"}`, http.StatusBadRequest)
			return
		}
		if _, ok := m.live[id]; !ok {
			http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
			return
		}
		delete(m.live, id)
		m.revoked[id] = true
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
	}
}

func (m *mockAAP) liveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

func (m *mockAAP) wasRevoked(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revoked[id]
}

// testConfigCreate writes the engine config pointing at the given address.
func testConfigCreate(tb testing.TB, b *aapBackend, s logical.Storage, address, token string) {
	tb.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   s,
		Data: map[string]interface{}{
			"address":         address,
			"token":           token,
			"tokens_api_path": "/api/gateway/v1",
			"skip_tls_verify": true,
		},
	})
	require.NoError(tb, err)
	require.False(tb, resp != nil && resp.IsError(), "config create errored: %v", resp)
}

// testRoleCreate writes a role.
func testRoleCreate(tb testing.TB, b *aapBackend, s logical.Storage, name string, d map[string]interface{}) {
	tb.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/" + name,
		Storage:   s,
		Data:      d,
	})
	require.NoError(tb, err)
	require.False(tb, resp != nil && resp.IsError(), "role create errored: %v", resp)
}

func TestBackend_Factory(t *testing.T) {
	b, _ := getTestBackend(t)
	require.NotNil(t, b)
	require.NotNil(t, b.Backend)
}

func TestBackend_getClient_notConfigured(t *testing.T) {
	b, s := getTestBackend(t)
	_, err := b.getClient(context.Background(), s)
	require.ErrorIs(t, err, errBackendNotConfigured)
}

func TestBackend_invalidate_resetsClient(t *testing.T) {
	m := newMockAAP("admin-token")
	srv := m.server(t)
	defer srv.Close()

	b, s := getTestBackend(t)
	testConfigCreate(t, b, s, srv.URL, "admin-token")

	// Build and cache the client.
	_, err := b.getClient(context.Background(), s)
	require.NoError(t, err)
	require.NotNil(t, b.client)

	// invalidate("config") must drop the cached client.
	b.invalidate(context.Background(), "config")
	require.Nil(t, b.client)
}
