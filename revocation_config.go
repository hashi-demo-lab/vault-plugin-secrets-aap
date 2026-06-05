package aap

import "fmt"

const (
	revocationAddressKey       = "revocation_address"
	revocationTokenKey         = "revocation_token"
	revocationTokensAPIPathKey = "revocation_tokens_api_path"
	revocationCACertKey        = "revocation_ca_cert"
	revocationSkipTLSVerifyKey = "revocation_skip_tls_verify"
)

func cloneConfig(config *aapConfig) *aapConfig {
	if config == nil {
		return nil
	}
	clone := *config
	return &clone
}

func addRevocationData(data map[string]interface{}, config *aapConfig) {
	if config == nil {
		return
	}
	data[revocationAddressKey] = config.Address
	data[revocationTokenKey] = config.Token
	data[revocationTokensAPIPathKey] = config.TokensAPIPath
	data[revocationCACertKey] = config.CACert
	data[revocationSkipTLSVerifyKey] = config.SkipTLSVerify
}

func configFromRevocationData(data map[string]interface{}) (*aapConfig, bool, error) {
	if _, ok := data[revocationAddressKey]; !ok {
		if _, ok := data[revocationTokenKey]; !ok {
			return nil, false, nil
		}
	}

	address, err := stringFromRevocationData(data, revocationAddressKey)
	if err != nil {
		return nil, true, err
	}
	token, err := stringFromRevocationData(data, revocationTokenKey)
	if err != nil {
		return nil, true, err
	}

	config := &aapConfig{
		Address:       address,
		Token:         token,
		TokensAPIPath: defaultTokensAPIPath,
	}
	if value, ok := data[revocationTokensAPIPathKey]; ok {
		apiPath, ok := value.(string)
		if !ok {
			return nil, true, fmt.Errorf("%s must be a string", revocationTokensAPIPathKey)
		}
		config.TokensAPIPath = apiPath
	}
	if value, ok := data[revocationCACertKey]; ok {
		caCert, ok := value.(string)
		if !ok {
			return nil, true, fmt.Errorf("%s must be a string", revocationCACertKey)
		}
		config.CACert = caCert
	}
	if value, ok := data[revocationSkipTLSVerifyKey]; ok {
		skip, ok := value.(bool)
		if !ok {
			return nil, true, fmt.Errorf("%s must be a bool", revocationSkipTLSVerifyKey)
		}
		config.SkipTLSVerify = skip
	}

	return config, true, nil
}

func stringFromRevocationData(data map[string]interface{}, key string) (string, error) {
	value, ok := data[key]
	if !ok {
		return "", fmt.Errorf("%s missing from revocation data", key)
	}
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	if s == "" {
		return "", fmt.Errorf("%s cannot be empty", key)
	}
	return s, nil
}
