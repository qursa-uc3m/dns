package dns

import (
	"fmt"
	"log"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func TestDilithium(t *testing.T) {
	// Inicializar el esquema de firma Dilithium
	signer := oqs.Signature{}
	err := signer.Init("Dilithium2", nil)
	if err != nil {
		log.Fatal("Error inicializando Dilithium:", err)
	}
	defer signer.Clean()

	// Generar claves
	publicKey, err := signer.GenerateKeyPair()
	if err != nil {
		log.Fatal("Error generando claves:", err)
	}

	// Mensaje a firmar
	message := []byte("Prueba de firma con Dilithium!")

	// Firmar el mensaje
	signature, err := signer.Sign(message)
	if err != nil {
		log.Fatal("Error firmando el mensaje:", err)
	}

	// Verificar la firma
	valid, err := signer.Verify(message, signature, publicKey)
	if err != nil {
		log.Fatal("Error verificando la firma:", err)
	}

	// Resultado
	if valid {
		fmt.Println("Firma válida!")
	} else {
		fmt.Println("Firma inválida!")
	}
}
