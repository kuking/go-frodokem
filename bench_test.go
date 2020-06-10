package go_frodokem

import (
	"testing"
)

func Benchmark_FrodoKEM_Keygen(b *testing.B) {
	for _, kem := range Variants() {
		b.Run(kem.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = kem.Keygen()
			}
		})
	}
}

func Benchmark_FrodoKEM_Encapsulate(b *testing.B) {
	for _, kem := range Variants() {
		b.Run(kem.name, func(b *testing.B) {
			pk, _ := kem.Keygen()
			for i := 0; i < b.N; i++ {
				_, _, _ = kem.Encapsulate(pk)
			}
		})
	}
}

func Benchmark_FrodoKEM_Dencapsulate(b *testing.B) {
	for _, kem := range Variants() {
		b.Run(kem.name, func(b *testing.B) {
			pk, sk := kem.Keygen()
			ct, _, _ := kem.Encapsulate(pk)
			for i := 0; i < b.N; i++ {
				_, _ = kem.Dencapsulate(sk, ct)
			}
		})
	}
}
