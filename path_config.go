package aap

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/automatedrotationutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/rotation"
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

	// RequestTimeout bounds every HTTP call to the AAP API. Zero means
	// defaultHTTPTimeout. Stored as nanoseconds (time.Duration) but accepted from
	// operators in seconds via the request_timeout field.
	RequestTimeout time.Duration `json:"request_timeout"`

	// TokenDescriptionPrefix is prepended to the description of every dynamically
	// minted token, so engine-issued tokens are identifiable — and sweepable — in
	// AAP. Empty leaves the role's description unmodified. Because AAP controls
	// token expiry globally (it ignores any client-supplied per-token expiry),
	// this description tag is the engine's primary lever for cleaning up tokens
	// orphaned by a crash.
	TokenDescriptionPrefix string `json:"token_description_prefix"`

	// AutomatedRotationParams carries the Rotation Manager schedule for the
	// privileged (root) credential: rotation_schedule/window or rotation_period,
	// and disable_automated_rotation. Embedded anonymously so its JSON-tagged
	// fields flatten into the config object.
	automatedrotationutil.AutomatedRotationParams

	// TokenID is the AAP id of the current bearer Token when the engine minted it
	// (via rotate-root), enabling the next rotation to revoke it. Zero for an
	// operator-supplied token whose id the engine does not know.
	TokenID int64 `json:"token_id"`
}

// pathConfig defines the config/ path and its schema.
func pathConfig(b *aapBackend) *framework.Path {
	fields := map[string]*framework.FieldSchema{
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
		"request_timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "Per-request timeout for calls to the AAP API (e.g. 30s, 1m). Defaults to 30s when unset.",
		},
		"token_description_prefix": {
			Type:        framework.TypeString,
			Description: "Optional string prepended to the description of every minted token. The engine also appends a unique request marker so ambiguous create failures can be swept safely.",
		},
	}
	// Adds rotation_schedule, rotation_window, rotation_period, and
	// disable_automated_rotation for the privileged (root) credential.
	automatedrotationutil.AddAutomatedRotationFields(fields)

	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixAAP,
		},
		Fields: fields,
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
	data := map[string]interface{}{
		"address":                  config.Address,
		"tokens_api_path":          config.TokensAPIPath,
		"skip_tls_verify":          config.SkipTLSVerify,
		"ca_cert_set":              config.CACert != "",
		"auth_type":                authType,
		"token_set":                config.Token != "",
		"username":                 config.Username,
		"password_set":             config.Password != "",
		"request_timeout":          int64(config.RequestTimeout.Seconds()),
		"token_description_prefix": config.TokenDescriptionPrefix,
	}
	config.PopulateAutomatedRotationData(data)
	return &logical.Response{Data: data}, nil
}

// pathConfigWrite creates or updates the configuration, then resets the cached
// client so subsequent operations use the new settings.
func (b *aapBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

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
	tokenRaw, tokenSupplied := data.GetOk("token")
	usernameRaw, usernameSupplied := data.GetOk("username")
	passwordRaw, passwordSupplied := data.GetOk("password")

	requestHasBearer := tokenSupplied && tokenRaw.(string) != ""
	requestHasBasic := (usernameSupplied && usernameRaw.(string) != "") ||
		(passwordSupplied && passwordRaw.(string) != "")
	if requestHasBearer && requestHasBasic {
		return logical.ErrorResponse("provide either token or username+password, not both"), nil
	}

	if tokenSupplied {
		config.Token = tokenRaw.(string)
		config.TokenID = 0
		if config.Token != "" {
			config.Username = ""
			config.Password = ""
			credSupplied = true
		}
	}
	if usernameSupplied {
		config.Username = usernameRaw.(string)
	}
	if passwordSupplied {
		config.Password = passwordRaw.(string)
		if config.Password != "" {
			credSupplied = true
		}
	}
	if requestHasBasic {
		config.Token = ""
		config.TokenID = 0
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

	// TypeDurationSecond already rejects negative inputs at field validation, so
	// these only need to convert seconds to a Duration.
	if rt, ok := data.GetOk("request_timeout"); ok {
		config.RequestTimeout = time.Duration(rt.(int)) * time.Second
	}

	if prefix, ok := data.GetOk("token_description_prefix"); ok {
		config.TokenDescriptionPrefix = prefix.(string)
	}

	if err := config.ParseAutomatedRotationFields(data); err != nil {
		return logical.ErrorResponse("invalid rotation settings: %s", err), nil
	}

	if configConnectionChanged(oldConfig, config) {
		config.TokenID = 0
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

	// Automated rotation mints a fresh privileged token for the engine, which is a
	// bearer-token-only operation (basic-auth rotation would mean changing a
	// password, which the engine cannot do). Reject the combination up front rather
	// than letting every scheduled rotation fail.
	if config.ShouldRegisterRotationJob() && config.Token == "" {
		return logical.ErrorResponse("automated rotation (rotation_period/rotation_schedule) requires bearer-token auth, not basic auth"), nil
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

	return b.handleConfigRotationJob(ctx, req, oldConfig, config), nil
}

// handleConfigRotationJob registers or deregisters the privileged credential's
// automated-rotation job with Vault's Rotation Manager to match the new config.
// It returns a response carrying any warnings (nil when there are none).
//
// Failures to (de)register are surfaced as warnings rather than hard errors: the
// connection config itself is already validated and persisted, and the Rotation
// Manager is a Vault Enterprise capability that is simply absent on CE — an
// operator on CE should still be able to configure the engine. The job is only
// touched when rotation state actually changes, so ordinary config writes never
// reach the (CE-unsupported) Rotation Manager at all.
func (b *aapBackend) handleConfigRotationJob(ctx context.Context, req *logical.Request, oldConfig, config *aapConfig) *logical.Response {
	resp := &logical.Response{}

	wasRegistered := oldConfig != nil && oldConfig.ShouldRegisterRotationJob()

	switch {
	case config.ShouldRegisterRotationJob():
		cfgReq := &rotation.RotationJobConfigureRequest{
			Name:             req.MountPoint + req.Path,
			MountPoint:       req.MountPoint,
			ReqPath:          req.Path,
			RotationSchedule: config.RotationSchedule,
			RotationWindow:   config.RotationWindow,
			RotationPeriod:   config.RotationPeriod,
		}
		if _, err := b.System().RegisterRotationJob(ctx, cfgReq); err != nil {
			resp.AddWarning(fmt.Sprintf("configuration saved, but registering the automated root-rotation job failed (rotation will not run until this succeeds): %s", err))
		}
	case config.DisableAutomatedRotation || wasRegistered:
		// Rotation was cleared or explicitly disabled; tear down any existing job.
		deregReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    req.Path,
		}
		if err := b.System().DeregisterRotationJob(ctx, deregReq); err != nil {
			resp.AddWarning(fmt.Sprintf("configuration saved, but deregistering the automated root-rotation job failed: %s", err))
		}
	}

	if len(resp.Warnings) == 0 {
		return nil
	}
	return resp
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

// pathConfigDelete removes the configuration and resets the client. If an
// automated root-rotation job was registered, it is deregistered so the Rotation
// Manager does not keep firing against a deleted mount config.
func (b *aapBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()

	resp := &logical.Response{}
	if cfg != nil && cfg.ShouldRegisterRotationJob() {
		deregReq := &rotation.RotationJobDeregisterRequest{
			MountPoint: req.MountPoint,
			ReqPath:    "config",
		}
		if err := b.System().DeregisterRotationJob(ctx, deregReq); err != nil {
			// Don't block deletion on an orphaned RM job; warn so it's greppable.
			b.Logger().Warn("failed to deregister root rotation job on config delete", "error", err)
			resp.AddWarning(fmt.Sprintf("config deleted, but deregistering the automated root-rotation job failed: %s", err))
		}
	}
	if len(resp.Warnings) == 0 {
		return nil, nil
	}
	return resp, nil
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

Optional operational settings:

  * "request_timeout" bounds each HTTP call to AAP (default 30s).

  * "token_description_prefix" is prepended to every minted token's description;
    the engine also appends a unique "vault-aap-request:<id>" marker so ambiguous
    create failures can be swept safely. AAP controls token expiry globally (via
    its OAUTH2_PROVIDER settings) and ignores any client-supplied per-token
    expiry. To bound how long an unrecoverable orphan can live, lower AAP's global
    access-token TTL.

  * "rotation_schedule"/"rotation_window" or "rotation_period", together with
    "disable_automated_rotation", register the privileged bearer token with
    Vault's Rotation Manager so it is rotated automatically (Enterprise only;
    requires bearer-token auth). This is the scheduled equivalent of the manual
    "config/rotate-root" endpoint.
`
)
