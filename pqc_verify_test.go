package dns

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func TestPQCVerifyRepeatedAndTampered(t *testing.T) {
	for _, candidate := range []struct {
		name string
		id   uint8
	}{
		{"ML-DSA-44", ML_DSA_44},
		{"Falcon-512", FALCON512},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			var signer oqs.Signature
			if err := signer.Init(candidate.name, nil); err != nil {
				t.Fatal(err)
			}
			pub, err := signer.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			private := append([]byte(nil), signer.ExportSecretKey()...)
			signer.Clean()
			key := &DNSKEY{
				Hdr:   RR_Header{Name: "cluster.local.", Rrtype: TypeDNSKEY, Class: ClassINET, Ttl: 300},
				Flags: ZONE, Protocol: 3, Algorithm: candidate.id,
				PublicKey: base64.StdEncoding.EncodeToString(pub),
			}
			for n := 1; n <= 3; n++ {
				rrset := []RR{&A{
					Hdr: RR_Header{Name: "svc.cluster.local.", Rrtype: TypeA, Class: ClassINET, Ttl: 5},
					A:   net.IPv4(10, 250, 0, byte(n)),
				}}
				now := uint32(time.Now().Unix())
				sig := &RRSIG{
					Hdr:       RR_Header{Rrtype: TypeRRSIG, Class: ClassINET, Ttl: 5},
					Algorithm: candidate.id, KeyTag: key.KeyTag(),
					SignerName: key.Hdr.Name, Inception: now - 60, Expiration: now + 3600,
				}
				if err := sig.SignWithPQC(nil, rrset, private); err != nil {
					t.Fatal(err)
				}
				if err := sig.Verify(key, rrset); err != nil {
					t.Fatalf("verification %d: %v", n, err)
				}
				other := []RR{Copy(rrset[0])}
				other[0].(*A).A = net.IPv4(10, 250, 0, byte(n+10))
				if err := sig.Verify(key, other); err == nil {
					t.Fatal("tampered RRset verified")
				}
			}
		})
	}
}
