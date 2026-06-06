package aap

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// configStoragePath is the single storage key holding the AAP connection.
const configStoragePath = "config"

// defaultTokensAPIPath is the AAP 2.5 platform gateway path that exposes the
// OAuth2 token endpoints. AAP 2.4 controllers use /api/controller/v2 instead.
const defaultTokensAPIPath = "/api/gateway/v1"

// aapConfig holds the engine's connection to AAP. The privileged credential is
// either a bearer Token or a Username/Password pair (basic auth); it is never
// returned on read.
type aapConfig struct {
	Address       string `json:"address"`
	Token         string `json:"token"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	TokensAPIPath string `json:"tokens_api_path"`
	CACert        string `json:"ca_cert"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`

	// TokenID is the AAP id of the current bearer Token when the engine minted it
	// (via rotate-root), enabling the next rotation to revoke it. Zero for an
	// operator-supplied token whose id the engine does not know.
	TokenID int64 `json:"token_id"`
}

// pathConfig defines the config/ path and its schema.
func pathConfig(b *aapBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixAAP,
		},
		Fields: map[string]*framework.FieldSchema{
			"address": {
				Type:        framework.TypeString,
				Description: "Base URL of the AAP platform, e.g. https://aap.example.com (no trailing API path).",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "AAP Address",
					Sensitive: false,
				},
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Privileged AAP OAuth2 token the engine uses to mint and revoke tokens (bearer auth). Provide this OR username+password.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "AAP Token",
					Sensitive: true,
				},
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Privileged AAP username for basic auth. Provide with password as an alternative to token.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "AAP Username",
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for the basic-auth username. Write-only; never returned on read.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "AAP Password",
					Sensitive: true,
				},
			},
			"tokens_api_path": {
				Type:        framework.TypeString,
				Default:     defaultTokensAPIPath,
				Description: "API base path exposing the token endpoints. Gateway (AAP 2.5+): /api/gateway/v1. Controller (AAP 2.4): /api/controller/v2.",
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "Optional PEM-encoded CA certificate to trust for the AAP TLS endpoint.",
			},
			"skip_tls_verify": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Skip TLS certificate verification. Insecure; for lab/self-signed use only.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.pathConfigWrite,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathConfigWrite,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback:                    b.pathConfigDelete,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck lets Vault distinguish create from update.
func (b *aapBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

// pathConfigRead returns the non-sensitive configuration. The token is never
// disclosed; only whether one is set.
func (b *aapBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	authType := "bearer"
	if config.Username != "" {
		authType = "basic"
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":         config.Address,
			"tokens_api_path": config.TokensAPIPath,
			"skip_tls_verify": config.SkipTLSVerify,
			"ca_cert_set":     config.CACert != "",
			"auth_type":       authType,
			"token_set":       config.Token != "",
			"username":        config.Username,
			"password_set":    config.Password != "",
		},
	}, nil
}

// pathConfigWrite creates or updates the configuration, then resets the cached
// client so subsequent operations use the new settings.
func (b *aapBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation
	oldConfig := cloneConfig(config)
	if config == nil {
		if !createOperation {
			return nil, errBackendNotConfigured
		}
		config = new(aapConfig)
	}

	if address, ok := data.GetOk("address"); ok {
		config.Address = address.(string)
	} else if createOperation {
		return logical.ErrorResponse("address is required"), nil
	}

	credSupplied := false
	if token, ok := data.GetOk("token"); ok {
		config.Token = token.(string)
		credSupplied = true
	}
	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
	}
	if password, ok := data.GetOk("password"); ok {
		config.Password = password.(string)
		credSupplied = true
	}

	if apiPath, ok := data.GetOk("tokens_api_path"); ok {
		config.TokensAPIPath = apiPath.(string)
	} else if config.TokensAPIPath == "" {
		config.TokensAPIPath = defaultTokensAPIPath
	}

	if caCert, ok := data.GetOk("ca_cert"); ok {
		config.CACert = caCert.(string)
	}

	if skip, ok := data.GetOk("skip_tls_verify"); ok {
		config.SkipTLSVerify = skip.(bool)
	}

	// Exactly one auth scheme: a bearer token, or basic username+password.
	hasBearer := config.Token != ""
	hasBasic := config.Username != "" || config.Password != ""
	switch {
	case hasBearer && hasBasic:
		return logical.ErrorResponse("provide either token or username+password, not both"), nil
	case hasBasic && (config.Username == "" || config.Password == ""):
		return logical.ErrorResponse("both username and password are required for basic auth"), nil
	case !hasBearer && !hasBasic:
		return logical.ErrorResponse("a credential is required: set token, or username and password"), nil
	}

	if !createOperation && !credSupplied && configConnectionChanged(oldConfig, config) {
		return logical.ErrorResponse("a credential (token or password) is required when changing AAP connection or TLS trust settings"), nil
	}
	if _, err := validateAddress(config.Address); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Verify the connection before persisting so a bad address, base path, TLS
	// trust setting, or privileged token is caught at config time rather than on
	// the first creds/ read. A verification failure rejects the write; to instead
	// store-and-warn, surface this as resp.AddWarning rather than an error.
	verifyClient, err := newClient(config)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := verifyClient.VerifyToken(ctx); err != nil {
		return logical.ErrorResponse("AAP connection verification failed: %s", err), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Force the client to be rebuilt with the new configuration.
	b.reset()

	return nil, nil
}

func configConnectionChanged(before, after *aapConfig) bool {
	if before == nil || after == nil {
		return false
	}
	return normalizeAddress(before.Address) != normalizeAddress(after.Address) ||
		normalizeBasePath(before.TokensAPIPath) != normalizeBasePath(after.TokensAPIPath) ||
		before.CACert != after.CACert ||
		before.SkipTLSVerify != after.SkipTLSVerify
}

// pathConfigDelete removes the configuration and resets the client.
func (b *aapBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

// getConfig loads and decodes the stored configuration, returning nil if none.
func getConfig(ctx context.Context, s logical.Storage) (*aapConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(aapConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

const (
	pathConfigHelpSynopsis    = "Configure the connection to Ansible Automation Platform."
	pathConfigHelpDescription = `
Configure the AAP secrets engine with the platform address, a privileged
OAuth2 token used to mint and revoke tokens, the token API base path, and
optional TLS trust settings.
`
)
