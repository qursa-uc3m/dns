package dns

import (
	"crypto"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Estructura que envuelva a oqs.Signature para cumplir con la interfaz crypto.Signer
type OQSSigner struct {
	privKey []byte
	pubKey  []byte
	signer  oqs.Signature
}

// Método Public() de la interfaz crypto.Signer
func (s *OQSSigner) Public() crypto.PublicKey {
	return s.pubKey
}

// Método Sign() de la interfaz crypto.Signer
func (s *OQSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	return s.signer.Sign(digest)
}

func (s *OQSSigner) ToDNSKEY() *DNSKEY {
	return &DNSKEY{PublicKey: string(s.pubKey)}
}

func TestDilithium(t *testing.T) {
	//crear una clave privada que sea compatible con Dilithium2.
	sigName := "Dilithium2"
	signer := oqs.Signature{}
	defer signer.Clean()

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	// Generar las claves
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	//clave secreta
	secretKey := signer.ExportSecretKey()

	// Crear un objeto OQSSigner con las claves y la firma
	oqsSigner := &OQSSigner{
		privKey: secretKey,
		pubKey:  pubKey,
		signer:  signer,
	}

	// Crear registro RR (por ejemplo, SRV record)
	srv := &SRV{
		Hdr: RR_Header{
			Name:   "example.com.",
			Rrtype: TypeSRV,
			Class:  ClassINET,
			Ttl:    3600,
		},
		Target:   "srv.example.com.",
		Port:     8080,
		Weight:   10,
		Priority: 5,
	}

	//crear los registros RRSIG necesarios para la firma
	sig := &RRSIG{
		Hdr: RR_Header{
			Name:   "example.com.",
			Rrtype: TypeRRSIG,
			Class:  ClassINET,
			Ttl:    3600,
		},
		TypeCovered: srv.Hdr.Rrtype,
		Labels:      uint8(CountLabel(srv.Hdr.Name)),
		OrigTtl:     srv.Hdr.Ttl,
		Expiration:  1620000000,
		Inception:   1610000000,
		KeyTag:      12345,
		SignerName:  "example.com",
		Algorithm:   DILITHIUM2,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	//Verificar la firma utilizando la clave pública de OQSSigner convertida a DNSKEY
	//hay que modificar el método Verify, pues se crean claves nuevas para firmar con dilithium
	//dnsKey := oqsSigner.ToDNSKEY() // Convertimos la clave pública en un tipo DNSKEY

	//err = sig.Verify(dnsKey, []RR{srv})
	//if err != nil {
	//	t.Errorf("Error al verificar la firma: %v", err)
	//} else {
	//	fmt.Println("Verificación exitosa.")
	//}
}
