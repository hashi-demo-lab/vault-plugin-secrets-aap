package aap

import (
	"fmt"
	"time"
)

const (
	revocationAddressKey        = "revocation_address"
	revocationTokenKey          = "revocation_token"
	revocationUsernameKey       = "revocation_username"
	revocationPasswordKey       = "revocation_password"
	revocationTokensAPIPathKey  = "revocation_tokens_api_path"
	revocationCACertKey         = "revocation_ca_cert"
	revocationSkipTLSVerifyKey  = "revocation_skip_tls_verify"
	revocationRequestTimeoutKey = "revocation_request_timeout"
)

func cloneConfig(config *aapConfig) *aapConfig {
	if config == nil {
		return nil
	}
	clone := *config
	return &clone
}

// addRevocationData snapshots the AAP connection — including the privileged
// credential (bearer token, or basic username/password) — into a lease's
// internal data so revocation succeeds even if the operator later changes or
// deletes the config. This is a deliberate tradeoff: it makes revocation robust
// at the cost of duplicating the privileged credential once per active lease.
//
// Security note on blast radius: the engine's own storage (config, role/*, WAL)
// is seal-wrapped via PathsSpecial, but these lease copies live in Vault core's
// expiration-manager storage, which a plugin cannot seal-wrap (it is
// barrier-encrypted only). Treat the privileged credential as present wherever
// leases are, and rotate it through this engine's config — never out-of-band in
// AAP — since out-of-band rotation would strand these snapshots on a dead
// credential.
func addRevocationData(data map[string]interface{}, config *aapConfig) {
	if config == nil {
		return
	}
	data[revocationAddressKey] = config.Address
	data[revocationTokenKey] = config.Token
	data[revocationUsernameKey] = config.Username
	data[revocationPasswordKey] = config.Password
	data[revocationTokensAPIPathKey] = config.TokensAPIPath
	data[revocationCACertKey] = config.CACert
	data[revocationSkipTLSVerifyKey] = config.SkipTLSVerify
	if config.RequestTimeout > 0 {
		data[revocationRequestTimeoutKey] = int64(config.RequestTimeout.Seconds())
	}
}

func configFromRevocationData(data map[string]interface{}) (*aapConfig, bool, error) {
	if _, ok := data[revocationAddressKey]; !ok {
		// Legacy/empty snapshot: fall back to the current config for revocation.
		if _, ok := data[revocationTokenKey]; !ok {
			return nil, false, nil
		}
	}

	address, err := requiredStringFromData(data, revocationAddressKey)
	if err != nil {
		return nil, true, err
	}

	config := &aapConfig{Address: address, TokensAPIPath: defaultTokensAPIPath}

	// Credential fields are optional individually — which are present depends on
	// the auth scheme. newClient validates that a usable scheme results.
	for key, dst := range map[string]*string{
		revocationTokenKey:    &config.Token,
		revocationUsernameKey: &config.Username,
		revocationPasswordKey: &config.Password,
		revocationCACertKey:   &config.CACert,
	} {
		v, err := optionalStringFromData(data, key)
		if err != nil {
			return nil, true, err
		}
		*dst = v
	}
	if value, ok := data[revocationTokensAPIPathKey]; ok {
		apiPath, ok := value.(string)
		if !ok {
			return nil, true, fmt.Errorf("%s must be a string", revocationTokensAPIPathKey)
		}
		if apiPath != "" {
			config.TokensAPIPath = apiPath
		}
	}
	if value, ok := data[revocationSkipTLSVerifyKey]; ok {
		skip, ok := value.(bool)
		if !ok {
			return nil, true, fmt.Errorf("%s must be a bool", revocationSkipTLSVerifyKey)
		}
		config.SkipTLSVerify = skip
	}
	if seconds, ok, err := optionalInt64FromData(data, revocationRequestTimeoutKey); err != nil {
		return nil, true, err
	} else if ok && seconds > 0 {
		config.RequestTimeout = time.Duration(seconds) * time.Second
	}

	return config, true, nil
}

// requiredStringFromData returns a non-empty string value or an error.
func requiredStringFromData(data map[string]interface{}, key string) (string, error) {
	s, err := optionalStringFromData(data, key)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", fmt.Errorf("%s cannot be empty", key)
	}
	return s, nil
}

// optionalStringFromData returns the string value for key, "" if absent, and an
// error only if present with a non-string type.
func optionalStringFromData(data map[string]interface{}, key string) (string, error) {
	value, ok := data[key]
	if !ok {
		return "", nil
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func optionalInt64FromData(data map[string]interface{}, key string) (int64, bool, error) {
	value, ok := data[key]
	if !ok {
		return 0, false, nil
	}
	switch v := value.(type) {
	case int:
		return int64(v), true, nil
	case int64:
		return v, true, nil
	case float64:
		if v != float64(int64(v)) {
			return 0, true, fmt.Errorf("%s must be a whole number of seconds", key)
		}
		return int64(v), true, nil
	default:
		n, err := coerceInt64(value, key)
		if err != nil {
			return 0, true, err
		}
		return n, true, nil
	}
}
