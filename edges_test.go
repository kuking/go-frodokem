package go_frodokem

import (
	"bytes"
	"testing"
)

func TestEncapsulateInvalidPublicKeySize(t *testing.T) {
	for name, kem := range suites() {
		for _, pkSize := range []int{1, 100, 1000} {
			pk := make([]byte, pkSize)
			t.Run(name, func(t *testing.T) {
				_, _, err := kem.Encapsulate(pk)
				if err == nil {
					t.Fatalf("kem.Encapsulate should have failed with pk size %v", len(pk))
				}
			})
		}
	}
}

func TestDencapsulateInvalidSecretKeySize(t *testing.T) {
	for name, kem := range suites() {
		for _, skSize := range []int{1, 100, 1000} {
			sk := make([]byte, skSize)
			t.Run(name, func(t *testing.T) {
				ct := make([]byte, kem.lenCtBytes)
				_, err := kem.Dencapsulate(sk, ct)
				if err == nil {
					t.Fatalf("kem.Dencapsulate should have failed with sk size %v", len(sk))
				}
			})
		}
	}
}

func TestDencapsulateInvalidSharedSecretSize(t *testing.T) {
	for name, kem := range suites() {
		for _, ctSize := range []int{1, 100, 1000} {
			ct := make([]byte, ctSize)
			t.Run(name, func(t *testing.T) {
				sk := make([]byte, kem.lenSkBytes)
				_, err := kem.Dencapsulate(sk, ct)
				if err == nil {
					t.Fatalf("kem.Dencapsulate should have failed with sk size %v", len(sk))
				}
			})
		}
	}
}

func TestDencapsulateCorruptedKem(t *testing.T) {
	for _, kem := range suites() {
		pk, sk := kem.Keygen()
		ct, ssEnc, err := kem.Encapsulate(pk)
		if err != nil {
			t.Error(err)
		}
		ct[123]++
		ssDec, err := kem.Dencapsulate(sk, ct)
		if err != nil {
			t.Error(err)
		}
		if bytes.Equal(ssEnc, ssDec) {
			t.Error("shared key should be different")
		}
	}
}
