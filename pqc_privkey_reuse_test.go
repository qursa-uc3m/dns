package dns

import (
	"bytes"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// TestPQCPrivkeyNotDestroyed verifies that SignWithPQC does not destroy
// the caller's private key material. This is a regression test for a bug
// where oqs.Signature.Clean() zeroed the shared privkey slice via
// MemCleanse after Init() stored a reference instead of a copy.
func TestPQCPrivkeyNotDestroyed(t *testing.T) {
	algorithms := []struct {
		algConst uint8
		oqsName  string
	}{
		{FALCON512, "Falcon-512"},
		{ML_DSA_44, "ML-DSA-44"},
		{MAYO1, "MAYO-1"},
	}

	for _, alg := range algorithms {
		t.Run(alg.oqsName, func(t *testing.T) {
			// Generate keys
			sig := oqs.Signature{}
			if err := sig.Init(alg.oqsName, nil); err != nil {
				t.Fatal(err)
			}
			pubKey, err := sig.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			secretKey := sig.ExportSecretKey()
			// Copy before Clean(); ExportSecretKey returns a reference
			// and Clean zeroes the underlying array.
			privKey := make([]byte, len(secretKey))
			copy(privKey, secretKey)
			sig.Clean()

			// Keep a reference copy to verify privkey isn't modified
			origKey := make([]byte, len(privKey))
			copy(origKey, privKey)

			oqsSigner := &OQSSigner{
				privKey: privKey,
				pubKey:  pubKey,
			}

			rrset := []RR{&SRV{
				Hdr:    RR_Header{Name: "example.com.", Rrtype: TypeSRV, Class: ClassINET, Ttl: 300},
				Target: "target.example.com.",
				Port:   443,
			}}

			// Sign 3 times with the same privkey slice
			for i := 0; i < 3; i++ {
				rrsig := &RRSIG{
					Hdr:        RR_Header{Name: "example.com.", Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 300},
					Algorithm:  alg.algConst,
					SignerName: "example.com.",
					KeyTag:     12345,
					Expiration: 1296534305,
					Inception:  1293942305,
				}

				if err := rrsig.SignWithPQC(oqsSigner, rrset, privKey); err != nil {
					t.Fatalf("signing iteration %d failed: %v", i+1, err)
				}

				if !bytes.Equal(privKey, origKey) {
					t.Fatalf("privkey was modified after signing iteration %d", i+1)
				}
			}
		})
	}
}
