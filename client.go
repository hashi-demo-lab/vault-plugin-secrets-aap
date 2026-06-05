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
	token      string // privileged bearer token used to mint/revoke
}

// aapToken models the JSON returned when AAP mints an OAuth2 token. AAP returns
// the secret value only once, at creation time.
type aapToken struct {
	ID          int64  `json:"id"`
	Token       string `json:"token"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
	Expires     string `json:"expires"`
}

// newClient builds an aapClient from stored configuration, including optional
// custom CA trust and TLS-verification skipping for lab environments.
func newClient(config *aapConfig) (*aapClient, error) {
	if config == nil {
		return nil, errBackendNotConfigured
	}
	if config.Token == "" {
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

	return &aapClient{
		httpClient: &http.Client{
			Timeout:   defaultHTTPTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
		address:  address,
		basePath: normalizeBasePath(config.TokensAPIPath),
		token:    config.Token,
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

// CreateToken mints a new AAP OAuth2 token with the given scope and
// description. The returned token's secret value is only available here.
func (c *aapClient) CreateToken(ctx context.Context, scope, description string) (*aapToken, error) {
	payload, err := json.Marshal(map[string]string{
		"scope":       scope,
		"description": description,
	})
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

// do sets auth headers, executes the request, and returns the body and status.
func (c *aapClient) do(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
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
