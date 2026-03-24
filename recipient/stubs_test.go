package recipient_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hyperscale-stack/enigma"
	"github.com/hyperscale-stack/enigma/recipient/awskms"
	"github.com/hyperscale-stack/enigma/recipient/azurekv"
	"github.com/hyperscale-stack/enigma/recipient/gcpkms"
	"github.com/hyperscale-stack/enigma/recipient/scwkm"
)

func TestCloudRecipientsAreExplicitStubs(t *testing.T) {
	gcp := gcpkms.New("projects/p/locations/l/keyRings/r/cryptoKeys/k", gcpkms.ModeClassical)
	aws := awskms.New("arn:aws:kms:region:acct:key/1")
	az := azurekv.New("https://vault.vault.azure.net/keys/key")
	scw := scwkm.New("fr-par/kms/key")

	if _, err := gcp.WrapKey(context.Background(), []byte("dek")); !errors.Is(err, enigma.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for gcp wrap")
	}
	if _, err := aws.WrapKey(context.Background(), []byte("dek")); !errors.Is(err, enigma.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for aws wrap")
	}
	if _, err := az.WrapKey(context.Background(), []byte("dek")); !errors.Is(err, enigma.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for azure wrap")
	}
	if _, err := scw.WrapKey(context.Background(), []byte("dek")); !errors.Is(err, enigma.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented for scw wrap")
	}
}
