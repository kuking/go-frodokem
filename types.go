package go_frodokem

import (
	"crypto/rand"
	"golang.org/x/crypto/sha3"
)

var variants = []FrodoKEM{
	Frodo640AES(), Frodo640SHAKE(),
	Frodo976AES(), Frodo976SHAKE(),
	Frodo1344AES(), Frodo1344SHAKE(),
}

// Returns all the FrodoKEM variants supported as an array
func Variants() []FrodoKEM {
	return variants
}

type FrodoKEM struct {
	// error_distribution
	name            string
	errDistribution []uint16
	tChi            []uint16
	d               int
	q               uint16
	n               int
	nBar            int
	mBar            int
	b               int
	lenSeedA        int
	lenZ            int
	lenMu           int
	lenSeedSE       int
	lenS            int
	lenK            int
	lenPkh          int
	lenSS           int
	lenChi          int
	lenSkBytes      int
	lenPkBytes      int
	lenCtBytes      int
	shake           func(msg []byte, digestLength int) []byte
	gen             func([]byte) [][]uint16
	rng             func([]byte)
}

// Returns a new FrodoKEM 640 AES variant (Generates 128 bits of secret)
func Frodo640AES() (f FrodoKEM) {
	f = FrodoKEM{
		name:            "Frodo640AES",
		errDistribution: []uint16{9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1},
		d:               15,
		q:               32768,
		n:               640,
		nBar:            8,
		mBar:            8,
		b:               2,
		lenSeedA:        128,
		lenZ:            128,
		lenMu:           128,
		lenSeedSE:       128,
		lenS:            128,
		lenK:            128,
		lenPkh:          128,
		lenSS:           128,
		lenChi:          16,
		lenSkBytes:      19888,
		lenPkBytes:      9616,
		lenCtBytes:      9720,
		shake:           shake128,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

// Returns a new FrodoKEM 640 SHAKE variant (Generates 128 bits of secret)
func Frodo640SHAKE() (f FrodoKEM) {
	f = Frodo640AES()
	f.name = "Frodo640Shake"
	f.shake = shake128
	f.gen = f.genSHAKE128
	return
}

// Returns a new FrodoKEM 976 AES variant (Generates 192 bits of secret)
func Frodo976AES() (f FrodoKEM) {
	f = FrodoKEM{
		name:            "Frodo976AES",
		errDistribution: []uint16{11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1},
		d:               16,
		q:               0, // means no mod in 16 bits uint
		n:               976,
		nBar:            8,
		mBar:            8,
		b:               3,
		lenSeedA:        128,
		lenZ:            128,
		lenMu:           192,
		lenSeedSE:       192,
		lenS:            192,
		lenK:            192,
		lenPkh:          192,
		lenSS:           192,
		lenChi:          16,
		lenSkBytes:      31296,
		lenPkBytes:      15632,
		lenCtBytes:      15744,
		shake:           shake256,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

// Returns a new FrodoKEM 976 SHAKE variant (Generates 192 bits of secret)
func Frodo976SHAKE() (f FrodoKEM) {
	f = Frodo976AES()
	f.name = "Frodo976Shake"
	f.gen = f.genSHAKE128
	return
}

// Returns a new FrodoKEM 1344 AES variant (Generates 256 bits of secret)
func Frodo1344AES() (f FrodoKEM) {
	f = FrodoKEM{
		name:            "Frodo1344AES",
		errDistribution: []uint16{18286, 14320, 6876, 2023, 364, 40, 2},
		d:               16,
		q:               0,
		n:               1344,
		nBar:            8,
		mBar:            8,
		b:               4,
		lenSeedA:        128,
		lenZ:            128,
		lenMu:           256,
		lenSeedSE:       256,
		lenS:            256,
		lenK:            256,
		lenPkh:          256,
		lenSS:           256,
		lenChi:          16,
		lenSkBytes:      43088,
		lenPkBytes:      21520,
		lenCtBytes:      21632,
		shake:           shake256,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

// Returns a new FrodoKEM 1344 SHAKE variant (Generates 256 bits of secret)
func Frodo1344SHAKE() (f FrodoKEM) {
	f = Frodo1344AES()
	f.name = "Frodo1344Shake"
	f.gen = f.genSHAKE128
	return
}

func sumUint16s(arr []uint16) (r uint16) {
	r = 0
	for _, v := range arr {
		r += v
	}
	return
}

func cdfZeroCentredSymmetric(chi []uint16) (tChi []uint16) {
	tChi = make([]uint16, len(chi))
	tChi[0] = (chi[0] / 2) - 1
	for z := 1; z < len(chi); z++ {
		tChi[z] = tChi[0] + sumUint16s(chi[1:z+1])
	}
	return
}

func cryptoRand(target []byte) {
	n, err := rand.Read(target)
	if err != nil {
		panic(err)
	}
	if len(target) != n {
		panic("could not generate enough randomness")
	}
}

func shake128(msg []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum128(hash, msg)
	return
}

func shake256(msg []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum256(hash, msg)
	return
}
