package aap

import (
	"context"
	"encoding/base64"
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
//
// It models the real AAP behavior that matters here: a minted token is owned by
// whichever identity authenticates the request. identities maps a bearer token
// to the user id it represents, so a bootstrap token mints as its own user.
type mockAAP struct {
	mu         sync.Mutex
	nextID     int64
	live       map[int64]string // id -> scope, for tokens that still exist
	revoked    map[int64]bool   // ids that received a DELETE
	created    int              // count of successful mints
	wantAuth   string           // admin bearer token
	users      map[string]int64 // username -> id, for ResolveUserID lookups
	identities map[string]int64 // bearer token -> owner user id
	mintUsers  map[int64]int64  // token id -> owner id recorded at mint
}

func newMockAAP(bearer string) *mockAAP {
	return &mockAAP{
		nextID:   100,
		live:     map[int64]string{},
		revoked:  map[int64]bool{},
		wantAuth: bearer,
		// Service accounts a per-user role can target in tests.
		users: map[string]int64{"admin": 2, "svc-deploy": 7, "svc-readonly": 8},
		// identities is keyed by the full Authorization header value -> owner id.
		// The admin bearer token mints as id 2 ("admin"); more are added per test.
		identities: map[string]int64{"Bearer " + bearer: 2},
		mintUsers:  map[int64]int64{},
	}
}

// addIdentity registers a bootstrap bearer token that mints as the given user id.
func (m *mockAAP) addIdentity(token string, userID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identities["Bearer "+token] = userID
}

// addBasicIdentity registers a basic-auth credential that mints as the given id.
func (m *mockAAP) addBasicIdentity(username, password string, userID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hdr := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	m.identities[hdr] = userID
}

// ownerFor returns the user id the request authenticates as (by exact
// Authorization header match), and whether the credential is known.
func (m *mockAAP) ownerFor(r *http.Request) (int64, bool) {
	id, ok := m.identities[r.Header.Get("Authorization")]
	return id, ok
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
	if _, ok := m.ownerFor(r); !ok {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	username := r.URL.Query().Get("username")
	results := []map[string]interface{}{}
	if username == "ambiguous" {
		// Two users sharing a name → ResolveUserID must reject as ambiguous.
		results = append(results,
			map[string]interface{}{"id": 11, "username": "ambiguous"},
			map[string]interface{}{"id": 12, "username": "ambiguous"})
	} else if id, ok := m.users[username]; ok {
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
	callerID, ok := m.ownerFor(r)
	if !ok {
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

	case r.Method == http.MethodGet && suffix != "":
		// Item read (tokenOwner) returns the token's owner.
		idStr := strings.TrimSuffix(suffix, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"detail":"bad id"}`, http.StatusBadRequest)
			return
		}
		scope, ok := m.live[id]
		if !ok {
			http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": id, "user": m.mintUsers[id], "scope": scope,
		})

	case r.Method == http.MethodPost && suffix == "":
		var body struct {
			Scope       string `json:"scope"`
			Description string `json:"description"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		id := m.nextID
		m.nextID++
		m.live[id] = body.Scope
		// AAP owns the token to the authenticating identity, ignoring any
		// requested owner — this is the behavior the engine relies on.
		m.mintUsers[id] = callerID
		// The minted token value is itself a usable bearer credential owned by
		// the caller (so rotate-root's new token authenticates).
		tokenValue := "secret-token-" + strconv.FormatInt(id, 10)
		m.identities["Bearer "+tokenValue] = callerID
		m.created++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":          id,
			"token":       tokenValue,
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
