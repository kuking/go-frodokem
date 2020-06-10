package main

import (
	"encoding/hex"
	"fmt"
	frodo "github.com/kuking/go-frodokem"
)

func main() {

	fmt.Println("==============================================================================")
	for _, kem := range frodo.Variants() {
		fmt.Println("Variant:", kem.Name())
		fmt.Println("|   Secret Key:", kem.SecretKeyLen())
		fmt.Println("|   Public Key:", kem.PublicKeyLen())
		fmt.Println("|  Cipher-text:", kem.CipherTextLen())
		fmt.Println("|Shared Secret:", kem.SharedSecretLen())
		fmt.Println()

		fmt.Println("Key-pair")
		pk, sk := kem.Keygen()
		fmt.Printf("Public Key: %s ... (%v bytes)\n", hex.EncodeToString(pk)[:40], len(pk))
		fmt.Printf("Secret Key: %s ... (%v bytes)\n", hex.EncodeToString(sk)[:45], len(sk))

		fmt.Println("\nEncapsulate")
		ct, ssEnc, _ := kem.Encapsulate(pk)
		fmt.Printf("  Cipher Text: %s ... (%v bytes)\n", hex.EncodeToString(ct)[:40], len(ct))
		fmt.Printf("Shared Secret: %s\n               (Generated with Public Key)\n", hex.EncodeToString(ssEnc))

		fmt.Println("Dencapsulate")
		ssDec, _ := kem.Dencapsulate(sk, ct)
		fmt.Printf("Shared Secret: %s\n               (Recovered with Secret Key + Cipher-text)\n", hex.EncodeToString(ssDec))
		fmt.Println("==============================================================================")
	}

}
