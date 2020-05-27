package go_frodokem

import (
	"testing"
)

func Benchmark_FrodoKEM_640_AES_Keygen(b *testing.B) {
	k := Frodo640AES()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}

func Benchmark_FrodoKEM_640_SHAKE_Keygen(b *testing.B) {
	k := Frodo640SHAKE()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}

func Benchmark_FrodoKEM_976_AES_Keygen(b *testing.B) {
	k := Frodo976AES()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}

func Benchmark_FrodoKEM_976_SHAKE_Keygen(b *testing.B) {
	k := Frodo976SHAKE()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}

func Benchmark_FrodoKEM_1344_AES_Keygen(b *testing.B) {
	k := Frodo1344AES()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}

func Benchmark_FrodoKEM_1344_SHAKE_Keygen(b *testing.B) {
	k := Frodo1344SHAKE()
	for i := 0; i < b.N; i++ {
		k.Keygen()
	}
}
