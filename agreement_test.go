package go_frodokem

import (
	"bytes"
	"testing"
)

// The following is an example of a key agreement mechanism using Frodo KEM
func TestKeyAgreementExample(t *testing.T) {
	for _, kem := range Variants() {

		// Stage 0, both Bob and Alice generates their long-lived key-pair, this is once in a while event.
		// We assume each other party receives the counter party public key in a secure way.
		//(To prevent a Man-In-The-Middle attack.)
		AlicePublic, AliceSecret := kem.Keygen()
		BobPublic, BobSecret := kem.Keygen()

		// Stage 1, Agreeing on temporary Key to be used in a symmetric cipher using an insecure channel
		// Alice generates a random number holding it in AliceShare and a cipherText for Bob (& ditto Bob for Alice).
		AliceToBobCipherText, AliceShare, err := kem.Encapsulate(BobPublic)
		BobToAliceCipherText, BobShare, err := kem.Encapsulate(AlicePublic)

		// Stage 2, both cipher texts are exchanged via an insecure channel.
		// Alice sends to Bob 'AliceToBobCipherText' over an insecure wire (& ditto Bob 'BobToAliceCipherText')

		// Stage 3, Alice has BobToAliceCipherText and can reconstruct BobShare using Alice Private key.
		AliceCopyOfBobShare, err := kem.Dencapsulate(AliceSecret, BobToAliceCipherText)
		if err != nil {
			t.Fatal(err) // if the cipherText was corrupted or compromised, Dencapsulate might err.
		}
		// Ditto  Bob
		BobCopyOfAliceShare, err := kem.Dencapsulate(BobSecret, AliceToBobCipherText)
		if err != nil {
			t.Fatal(err) // ditto, might fail if compromised or corrupted ciphertext.
		}

		// In practice, the following assertion can not be verified, as AliceCopyOfBobShare and BobShare will be in
		// different computers. They should be equal. The real-life verification happens when the final derived key
		// from each party become the same value, enabling the symmetric cipher to work correctly. Below in stage 4.
		if !bytes.Equal(AliceCopyOfBobShare, BobShare) {
			t.Fatal("Alice failed to reconstruct Bob Shared secret")
		}
		// ditto Bob
		if !bytes.Equal(BobCopyOfAliceShare, AliceShare) {
			t.Fatal("Bob failed to reconstruct Alice Shared secret")
		}

		// Stage 4, Key exchange has occurred, now both parties can generate a common shared secret that is built using
		// both parties shared secret, the shared secret was not transfer in plain-text over the wire, but derived from
		// the ciphertexts. If modified in any way or form, the final key won't be the same for both parties.
		// The final joined key can be used for a session key in a symmetric cipher (i.e. AES)
		AliceCopyOfSharedKey := append(AliceShare, AliceCopyOfBobShare...)
		BobCopyOfSharedKey := append(BobCopyOfAliceShare, BobShare...)
		if !bytes.Equal(AliceCopyOfSharedKey, BobCopyOfSharedKey) {
			t.Fatal("Alice and Bob did not reconstruct the same shard secret using both parties shared secrets" +
				"the symmetric cipher that depends on this will not be able to decrypt the other's party messages.")
		}
		// happy
	}

}
