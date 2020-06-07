package go_frodokem

import (
	"testing"
)

func suites() map[string]FrodoKEM {
	return map[string]FrodoKEM{
		"   640 AES": Frodo640AES(),
		"   976 AES": Frodo976AES(),
		"  1344 AES": Frodo1344AES(),
		" 640 SHAKE": Frodo640SHAKE(),
		" 976 SHAKE": Frodo976SHAKE(),
		"1344 SHAKE": Frodo1344SHAKE(),
	}
}

func Benchmark_FrodoKEM_Keygen(b *testing.B) {
	for name, kem := range suites() {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = kem.Keygen()
			}
		})
	}
}

func Benchmark_FrodoKEM_Encapsulate(b *testing.B) {
	for name, kem := range suites() {
		b.Run(name, func(b *testing.B) {
			pk, _ := kem.Keygen()
			for i := 0; i < b.N; i++ {
				_, _, _ = kem.Encapsulate(pk)
			}
		})
	}
}

func Benchmark_FrodoKEM_Dencapsulate(b *testing.B) {
	for name, kem := range suites() {
		b.Run(name, func(b *testing.B) {
			pk, sk := kem.Keygen()
			ct, _, _ := kem.Encapsulate(pk)
			for i := 0; i < b.N; i++ {
				_, _ = kem.Dencapsulate(sk, ct)
			}
		})
	}
}
func Benchmark_FrodoKEM_DencapsulateFast(b *testing.B) {
	for name, kem := range suites() {
		b.Run(name, func(b *testing.B) {
			pk, sk := kem.Keygen()
			ct, _, _ := kem.Encapsulate(pk)
			for i := 0; i < b.N; i++ {
				_, _ = kem.DencapsulateFast(sk, ct)
			}
		})
	}
}
