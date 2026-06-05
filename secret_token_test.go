package aap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCoerceTokenID covers every type the token_id can arrive as. The float64
// case is the important one: when Vault persists a lease and reloads it, the
// secret's InternalData round-trips through JSON and integers come back as
// float64 — this is the real production revoke path.
func TestCoerceTokenID(t *testing.T) {
	tests := []struct {
		name    string
		in      interface{}
		want    int64
		wantErr bool
	}{
		{"int64", int64(42), 42, false},
		{"int", 42, 42, false},
		{"float64 (legacy JSON round-trip)", float64(42), 42, false},
		{"string", "42", 42, false},
		// Exactness above 2^53: a string round-trips precisely where a float64
		// would corrupt the last digit (9007199254740993 -> ...992).
		{"large string > 2^53", "9007199254740993", 9007199254740993, false},
		{"json.Number", json.Number("12345"), 12345, false},
		{"bad string", "not-a-number", 0, true},
		{"unexpected type", []byte("42"), 0, true},
		{"nil", nil, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coerceTokenID(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
