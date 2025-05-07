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

func TestFalcon512(t *testing.T) {
	//crear una clave privada que sea compatible con FALCON512.
	sigName := "Falcon-512"
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
		Algorithm:   FALCON512,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

	/*Verificar la firma utilizando la clave pública de OQSSigner convertida a DNSKEY
	dnsKey := oqsSigner.ToDNSKEY() // Convertimos la clave pública en un tipo DNSKEY
	fmt.Printf("Clave pública convertida a DNSKEY: %x\n", dnsKey.PublicKey)

	err = sig.Verify(dnsKey, []RR{srv})
	if err != nil {
		t.Errorf("Error al verificar la firma: %v", err)
	} else {
		fmt.Println("Verificación exitosa.")
	}*/
}

func TestDilithium2(t *testing.T) {
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

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestSphincsSha2(t *testing.T) {
	//crear una clave privada que sea compatible con SPHINCS_SHA2.
	sigName := "SPHINCS+-SHA2-128s-simple"
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
		Algorithm:   SPHINCS_SHA2,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestMayo1(t *testing.T) {
	//crear una clave privada que sea compatible con MAYO1.
	sigName := "MAYO-1"
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
		Algorithm:   MAYO1,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestFalcon1024(t *testing.T) {
	//crear una clave privada que sea compatible con FALCON1024.
	sigName := "Falcon-1024"
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
		Algorithm:   FALCON1024,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())
}

func TestDilithium3(t *testing.T) {
	//crear una clave privada que sea compatible con Dilithium3.
	sigName := "Dilithium3"
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
		Algorithm:   DILITHIUM3,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestSphincsShake(t *testing.T) {
	//crear una clave privada que sea compatible con SPHINCS_SHAKE.
	sigName := "SPHINCS+-SHAKE-128s-simple"
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
		Algorithm:   SPHINCS_SHAKE,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestMayo3(t *testing.T) {
	//crear una clave privada que sea compatible con MAYO3.
	sigName := "MAYO-3"
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
		Algorithm:   MAYO3,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestFalconPadded512(t *testing.T) {
	//crear una clave privada que sea compatible con FALCONPADDED512.
	sigName := "Falcon-padded-512"
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
		Algorithm:   FALCONPADDED512,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())
}

func TestDilithium5(t *testing.T) {
	//crear una clave privada que sea compatible con Dilithium5.
	sigName := "Dilithium5"
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
		Algorithm:   DILITHIUM5,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())

}

func TestFalconPadded1024(t *testing.T) {
	//crear una clave privada que sea compatible con FALCONPADDED512.
	sigName := "Falcon-padded-1024"
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
		Algorithm:   FALCONPADDED1024,
	}

	// Firmar el registro RRSIG utilizando el firmante
	err = sig.SignWithPQC(oqsSigner, []RR{srv}, secretKey)
	if err != nil {
		log.Fatalf("Error al firmar: %v", err)
	} else {
		fmt.Println("Firma exitosa.")
	}

	fmt.Printf("Clave pública generada: %x\n", pubKey)
	fmt.Printf("Clave pública usada en DNSKEY: %x\n", oqsSigner.Public())
}
