package aap

import "errors"

var (
	// errBackendNotConfigured is returned when an operation needs the AAP
	// connection but no config has been written yet.
	errBackendNotConfigured = errors.New("AAP backend not configured: write the 'config' path first")

	// errMissingToken indicates the configured admin token is empty.
	errMissingToken = errors.New("missing AAP token in configuration")

	// errMissingAddress indicates the configured AAP address is empty.
	errMissingAddress = errors.New("missing AAP address in configuration")
)
