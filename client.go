package aap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultHTTPTimeout bounds every call to the AAP API.
const defaultHTTPTimeout = 30 * time.Second

// aapClient is a thin HTTP client for the AAP token API. AAP ships no official
// Go SDK, so we talk to its REST endpoints directly.
type aapClient struct {
	httpClient *http.Client
	address    string // normalized, no trailing slash, e.g. https://aap.example.com
	basePath   string // normalized, leading slash, no trailing slash, e.g. /api/gateway/v1
	auth       authenticator
}

// authenticator applies an authentication scheme to outgoing AAP requests. It
// is the seam that lets the engine support multiple AAP auth schemes (bearer
// token today, HTTP basic, others later) without the request code caring which.
type authenticator interface {
	authenticate(req *http.Request)
	scheme() string
}

// bearerAuth authenticates with an OAuth2 bearer token (the engine's default and
// the only scheme usable for per-user bootstrap tokens).
type bearerAuth struct{ token string }

func (a bearerAuth) authenticate(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.token)
}
func (a bearerAuth) scheme() string { return "bearer" }

// basicAuth authenticates with an AAP username and password.
type basicAuth struct{ username, password string }

func (a basicAuth) authenticate(req *http.Request) { req.SetBasicAuth(a.username, a.password) }
func (a basicAuth) scheme() string                 { return "basic" }

// authenticatorFromConfig selects the auth scheme from stored config: basic when
// a username/password pair is present, otherwise a bearer token.
func authenticatorFromConfig(config *aapConfig) (authenticator, error) {
	switch {
	case config.Username != "" && config.Password != "":
		return basicAuth{username: config.Username, password: config.Password}, nil
	case config.Token != "":
		return bearerAuth{token: config.Token}, nil
	default:
		return nil, errMissingToken
	}
}

// aapToken models the JSON returned when AAP mints an OAuth2 token. AAP returns
// the secret value only once, at creation time.
type aapToken struct {
	ID          int64  `json:"id"`
	Token       string `json:"token"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
	Application int64  `json:"application"` // OAuth2 application id, 0/null for personal tokens
}

// newClient builds an aapClient from stored configuration, selecting the auth
// scheme from the config (bearer token or basic username/password).
func newClient(config *aapConfig) (*aapClient, error) {
	if config == nil {
		return nil, errBackendNotConfigured
	}
	auth, err := authenticatorFromConfig(config)
	if err != nil {
		return nil, err
	}
	return newClientWithAuth(config, auth)
}

// newClientWithAuth builds an aapClient using an explicit authenticator. It is
// the seam for schemes the config doesn't select directly — notably per-user
// bootstrap tokens, which always authenticate as a bearer token regardless of
// how the engine's own config authenticates.
func newClientWithAuth(config *aapConfig, auth authenticator) (*aapClient, error) {
	if config == nil {
		return nil, errBackendNotConfigured
	}
	if auth == nil {
		return nil, errMissingToken
	}
	if config.Address == "" {
		return nil, errMissingAddress
	}
	address, err := validateAddress(config.Address)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: config.SkipTLSVerify, //nolint:gosec // opt-in for lab/self-signed CAs, documented as insecure
	}
	if config.CACert != "" {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM([]byte(config.CACert)); !ok {
			return nil, fmt.Errorf("failed to parse ca_cert PEM data")
		}
		tlsConfig.RootCAs = pool
	}

	timeout := defaultHTTPTimeout
	if config.RequestTimeout > 0 {
		timeout = config.RequestTimeout
	}

	return &aapClient{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		address:  address,
		basePath: normalizeBasePath(config.TokensAPIPath),
		auth:     auth,
	}, nil
}

// validateAddress normalizes and rejects plaintext endpoints for bearer tokens.
func validateAddress(address string) (string, error) {
	normalized := normalizeAddress(address)
	u, err := url.Parse(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid AAP address: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("AAP address must use https")
	}
	if u.Host == "" {
		return "", fmt.Errorf("AAP address must include a host")
	}
	return normalized, nil
}

// normalizeAddress strips any trailing slash from the configured address.
func normalizeAddress(address string) string {
	return strings.TrimRight(strings.TrimSpace(address), "/")
}

// normalizeBasePath ensures the API base path has a leading slash and no
// trailing slash, defaulting to the AAP 2.5 gateway path when empty.
func normalizeBasePath(basePath string) string {
	bp := strings.TrimSpace(basePath)
	if bp == "" {
		bp = defaultTokensAPIPath
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	return strings.TrimRight(bp, "/")
}

// tokensURL builds the collection or item URL for the tokens endpoint.
func (c *aapClient) tokensURL(suffix string) string {
	return fmt.Sprintf("%s%s/tokens/%s", c.address, c.basePath, suffix)
}

// usersURL builds a URL under the users collection (suffix may be a query
// string such as "?username=alice").
func (c *aapClient) usersURL(suffix string) string {
	return fmt.Sprintf("%s%s/users/%s", c.address, c.basePath, suffix)
}

// applicationsURL builds a URL under the applications collection.
func (c *aapClient) applicationsURL(suffix string) string {
	return fmt.Sprintf("%s%s/applications/%s", c.address, c.basePath, suffix)
}

// aapApplication is the subset of an AAP OAuth2 application needed to resolve a
// role's application name to the numeric id the token-creation payload requires.
type aapApplication struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ResolveApplicationID looks up an AAP OAuth2 application by exact name and
// returns its numeric id, erroring on no match or ambiguity.
func (c *aapClient) ResolveApplicationID(ctx context.Context, name string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.applicationsURL("?name="+url.QueryEscape(name)), nil)
	if err != nil {
		return 0, err
	}

	respBody, status, err := c.do(req)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("AAP application lookup failed (HTTP %d): %s", status, truncate(respBody))
	}

	var list struct {
		Results []aapApplication `json:"results"`
	}
	if err := json.Unmarshal(respBody, &list); err != nil {
		return 0, fmt.Errorf("failed to decode AAP application lookup: %w", err)
	}

	var matches []aapApplication
	for _, a := range list.Results {
		if a.Name == name {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("AAP application %q not found", name)
	case 1:
		if matches[0].ID <= 0 {
			return 0, fmt.Errorf("AAP returned an invalid id for application %q", name)
		}
		return matches[0].ID, nil
	default:
		return 0, fmt.Errorf("AAP application %q is ambiguous (%d matches)", name, len(matches))
	}
}

// aapUser is the subset of an AAP user object needed to resolve a role's
// username to the numeric id the token-creation payload requires.
type aapUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// ResolveUserID looks up an AAP user by exact username and returns its numeric
// id. It errors if no user matches or if the lookup is ambiguous, so a token is
// never bound to the wrong identity.
func (c *aapClient) ResolveUserID(ctx context.Context, username string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.usersURL("?username="+url.QueryEscape(username)), nil)
	if err != nil {
		return 0, err
	}

	respBody, status, err := c.do(req)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("AAP user lookup failed (HTTP %d): %s", status, truncate(respBody))
	}

	var list struct {
		Results []aapUser `json:"results"`
	}
	if err := json.Unmarshal(respBody, &list); err != nil {
		return 0, fmt.Errorf("failed to decode AAP user lookup: %w", err)
	}

	// The ?username= filter should already be exact, but match defensively so a
	// substring or case quirk cannot bind a token to the wrong user.
	var matches []aapUser
	for _, u := range list.Results {
		if u.Username == username {
			matches = append(matches, u)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("AAP user %q not found", username)
	case 1:
		if matches[0].ID <= 0 {
			return 0, fmt.Errorf("AAP returned an invalid id for user %q", username)
		}
		return matches[0].ID, nil
	default:
		return 0, fmt.Errorf("AAP user %q is ambiguous (%d matches)", username, len(matches))
	}
}

// CreateToken mints a new AAP OAuth2 personal token with the given scope and
// description. The returned token's secret value is only available here.
//
// The token is owned by whichever identity this client authenticates as (AAP
// assigns ownership from the caller, ignoring any requested owner). Per-user
// issuance is therefore achieved by authenticating with that user's own token —
// see the role bootstrap_token handling in createToken.
func (c *aapClient) CreateToken(ctx context.Context, scope, description string) (*aapToken, error) {
	return c.createTokenForApp(ctx, scope, description, 0)
}

// createTokenForApp mints a token, optionally bound to an OAuth2 application when
// applicationID > 0 (an application-scoped token); 0 mints a personal token.
//
// Note on expiry: AAP controls token lifetime globally via its OAUTH2_PROVIDER
// settings and ignores any client-supplied per-token "expires", so the engine
// does not attempt to set one — the Vault lease is the per-token clock.
func (c *aapClient) createTokenForApp(ctx context.Context, scope, description string, applicationID int64) (*aapToken, error) {
	reqBody := map[string]interface{}{
		"scope":       scope,
		"description": description,
	}
	if applicationID > 0 {
		reqBody["application"] = applicationID
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokensURL(""), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	body, status, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, fmt.Errorf("AAP token creation failed (HTTP %d): %s", status, truncate(body))
	}

	var token aapToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if token.Token == "" {
		return nil, fmt.Errorf("AAP returned an empty token value")
	}
	if token.ID <= 0 {
		return nil, fmt.Errorf("AAP returned an invalid token id")
	}
	return &token, nil
}

// VerifyToken performs a lightweight authenticated GET against the tokens
// collection to confirm the configured address, base path, TLS trust, and
// privileged token are all usable before the engine starts minting. It is
// called on config write so misconfiguration surfaces immediately rather than
// on the first creds/ read.
//
// A 401/403 means the privileged token is wrong or unauthorized; any other
// non-2xx or transport error means the endpoint is unreachable or misrouted.
// Callers treat a non-nil error as a reason to reject the config write.
func (c *aapClient) VerifyToken(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.tokensURL(""), nil)
	if err != nil {
		return err
	}

	body, status, err := c.do(req)
	if err != nil {
		return fmt.Errorf("could not reach AAP at %s%s: %w", c.address, c.basePath, err)
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("AAP rejected the configured token (HTTP %d): %s", status, truncate(body))
	default:
		return fmt.Errorf("unexpected response verifying AAP connection (HTTP %d): %s", status, truncate(body))
	}
}

// RevokeToken deletes an AAP token by ID. A 404 is treated as success so that
// revocation is idempotent — Vault may retry, and a token already gone is the
// desired end state.
func (c *aapClient) RevokeToken(ctx context.Context, id int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.tokensURL(fmt.Sprintf("%d/", id)), nil)
	if err != nil {
		return err
	}

	body, status, err := c.do(req)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK, http.StatusAccepted, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("AAP token revocation failed (HTTP %d): %s", status, truncate(body))
	}
}

// tokenDetail reads a token object's owner and application-binding ids. AAP
// returns null for an unset application, which decodes to 0. Used by the
// ownership and application-binding guards.
func (c *aapClient) tokenDetail(ctx context.Context, id int64) (user, application int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.tokensURL(fmt.Sprintf("%d/", id)), nil)
	if err != nil {
		return 0, 0, err
	}
	body, status, err := c.do(req)
	if err != nil {
		return 0, 0, err
	}
	if status != http.StatusOK {
		return 0, 0, fmt.Errorf("AAP token read failed (HTTP %d): %s", status, truncate(body))
	}
	var detail struct {
		User        int64 `json:"user"`
		Application int64 `json:"application"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		return 0, 0, fmt.Errorf("failed to decode token detail: %w", err)
	}
	return detail.User, detail.Application, nil
}

// tokenOwner returns the AAP user id that owns a token (per-user mint guard).
func (c *aapClient) tokenOwner(ctx context.Context, id int64) (int64, error) {
	user, _, err := c.tokenDetail(ctx, id)
	return user, err
}

// tokenApplication returns the OAuth2 application id a token is bound to, 0 if
// none (application-scoped mint guard).
func (c *aapClient) tokenApplication(ctx context.Context, id int64) (int64, error) {
	_, app, err := c.tokenDetail(ctx, id)
	return app, err
}

// do sets auth headers, executes the request, and returns the body and status.
func (c *aapClient) do(req *http.Request) ([]byte, int, error) {
	c.auth.authenticate(req)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("AAP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read AAP response body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// truncate keeps error messages from dumping huge HTML error pages.
func truncate(body []byte) string {
	const max = 256
	s := strings.TrimSpace(string(body))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
