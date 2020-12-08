package go_frodokem

import (
	"bytes"
	"testing"
)

// The following is an example of a key agreement mechanism using Frodo KEM
func TestKeyAgreementExample(t *testing.T) {
	for _, kem := range Variants() {

		// Stage 1, both Bob and Alice generates their long-lived key-pair, this is once in a while event.
		// We assume each other party receives the counter party public key in a secure way.
		//(To prevent a Man-In-The-Middle attack.)

		AlicePublic, AliceSecret := kem.Keygen()
		BobPublic, BobSecret := kem.Keygen()
		// After this stage, we assume Bob has Alice' public key, and Alice has Bob' public key

		// Alice generates a random number holding it in AliceShare and a cipherText for Bob.
		// ditto Bob for Alice
		AliceToBobCipherText, AliceShare, err := kem.Encapsulate(BobPublic)
		BobToAliceCipherText, BobShare, err := kem.Encapsulate(AlicePublic)

		// Alice sends to Bob 'AliceToBobCipherText' over an insecure channel
		// ditto Bob 'BobToAliceCipherText'

		// Alice has BobToAliceCipherText and can reconstruct BobShare using Alice Private key.
		AliceCopyOfBobShare, err := kem.Dencapsulate(AliceSecret, BobToAliceCipherText)
		if err != nil {
			t.Fatal(err)
		}

		// Ditto  Bob
		BobCopyOfAliceShare, err := kem.Dencapsulate(BobSecret, AliceToBobCipherText)
		if err != nil {
			t.Fatal(err)
		}

		// In practice, the following assertion can not be verified, as AliceCopyOfBobShare and BobShare will be in
		// different computers. They should be equal. The real-life verification happens when the final derived key
		// from each party become the same value, enabling the symmetric cipher to work. Below.
		if !bytes.Equal(AliceCopyOfBobShare, BobShare) {
			t.Fatal("Alice failed to reconstruct Bob Shared secret")
		}
		// ditto Bob
		if !bytes.Equal(BobCopyOfAliceShare, AliceShare) {
			t.Fatal("Bob failed to reconstruct Alice Shared secret")
		}

		// Key exchange has occurred, now both parties can generate a common shared secret that is built using both
		// parties shared secret, the share was nos transfered via the wire, but the cipher text which is considered
		// secure. The final joined key can be used for a session key (i.e. AES)
		AliceCopyOfSharedKey := append(AliceShare, AliceCopyOfBobShare...)
		BobCopyOfSharedKey := append(BobCopyOfAliceShare, BobShare...)
		if !bytes.Equal(AliceCopyOfSharedKey, BobCopyOfSharedKey) {
			t.Fatal("Alice and Bob did not reconstruct the same shard secret using both parties shared secrets" +
				"the symmetric cipher that depends on this will not be able to decrypt the other's party messages.")
		}
		// happy
	}

}
