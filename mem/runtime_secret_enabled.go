//go:build enigma_runtime_secret

package mem

// RuntimeSecretEnabled indicates that the optional runtime secret integration build tag was enabled.
// This package still provides best-effort memory hygiene and does not claim hard guarantees.
const RuntimeSecretEnabled = true
