package go_frodokem

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/sha3"
)

type FrodoKEM struct {
	// error_distribution
	errDistribution []uint16
	tChi            []uint16
	D               int
	q               uint16
	n               int
	nBar            int
	mBar            int
	B               int
	lenSeedA        int
	lenSeedABytes   int
	lenZ            int
	lenZBytes       int
	lenMu           int
	lenMuBytes      int
	lenSeedSE       int
	lenSeedSEBytes  int
	lenS            int
	lenSBytes       int
	lenK            int
	lenKBytes       int
	lenPkh          int
	lenPkhBytes     int
	lenSS           int
	lenSSBytes      int
	lenChi          int
	lenChiBytes     int
	lenSkBytes      int
	lenPkBytes      int
	lenCtBytes      int
	shake           func(msg []byte, digestLength int) []byte
	gen             func([]byte) [][]uint16
	rng             func([]byte)
}

func (k *FrodoKEM) genAES128(seedA []byte) (A [][]uint16) {
	A = make([][]uint16, k.n)
	for i := 0; i < k.n; i++ {
		A[i] = make([]uint16, k.n)
	}
	cipher, err := aes.NewCipher(seedA)
	if err != nil {
		panic(err)
	}
	var b = [16]byte{}
	var c = [16]byte{}
	for i := 0; i < k.n; i++ {
		for j := 0; j < k.n; j += 8 {
			binary.LittleEndian.PutUint16(b[0:2], uint16(i))
			binary.LittleEndian.PutUint16(b[2:4], uint16(j))
			cipher.Encrypt(c[:], b[:])
			for l := 0; l < 8; l++ {
				A[i][j+l] = binary.LittleEndian.Uint16(c[l*2 : (l+1)*2])
				if k.q != 0 {
					A[i][j+l] %= k.q
				}
			}

		}
	}
	return
}

func (k *FrodoKEM) genSHAKE128(seedA []byte) (A [][]uint16) {
	A = make([][]uint16, k.n)
	for i := 0; i < k.n; i++ {
		A[i] = make([]uint16, k.n)
	}
	var tmp = make([]byte, 2+len(seedA))
	copy(tmp[2:], seedA)
	for i := 0; i < k.n; i++ {
		binary.LittleEndian.PutUint16(tmp[0:], uint16(i))
		c := Shake128(tmp, 2*k.n)
		for j := 0; j < k.n; j++ {
			A[i][j] = binary.LittleEndian.Uint16(c[j*2 : (j+1)*2])
			if k.q != 0 {
				A[i][j] %= k.q
			}
		}
	}
	return
}

func Frodo640AES() (f FrodoKEM) {
	f = FrodoKEM{
		errDistribution: []uint16{9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1},
		D:               15,
		q:               32768,
		n:               640,
		nBar:            8,
		mBar:            8,
		B:               2,
		lenSeedA:        128,
		lenSeedABytes:   128 / 8,
		lenZ:            128,
		lenZBytes:       128 / 8,
		lenMu:           128,
		lenMuBytes:      128 / 8,
		lenSeedSE:       128,
		lenSeedSEBytes:  128 / 8,
		lenS:            128,
		lenSBytes:       128 / 8,
		lenK:            128,
		lenKBytes:       128 / 8,
		lenPkh:          128,
		lenPkhBytes:     128 / 8,
		lenSS:           128,
		lenSSBytes:      128 / 8,
		lenChi:          16,
		lenChiBytes:     16 / 8,
		lenSkBytes:      19888,
		lenPkBytes:      9616,
		lenCtBytes:      9720,
		shake:           Shake128,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

func Frodo640SHAKE() (f FrodoKEM) {
	f = Frodo640AES()
	f.shake = Shake128
	f.gen = f.genSHAKE128
	return
}

func Frodo976AES() (f FrodoKEM) {
	f = FrodoKEM{
		errDistribution: []uint16{11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1},
		D:               16,
		q:               0, // means no mod in 16 bits uint
		n:               976,
		nBar:            8,
		mBar:            8,
		B:               3,
		lenSeedA:        128,
		lenSeedABytes:   128 / 8,
		lenZ:            128,
		lenZBytes:       128 / 8,
		lenMu:           192,
		lenMuBytes:      192 / 8,
		lenSeedSE:       192,
		lenSeedSEBytes:  192 / 8,
		lenS:            192,
		lenSBytes:       192 / 8,
		lenK:            192,
		lenKBytes:       192 / 8,
		lenPkh:          192,
		lenPkhBytes:     192 / 8,
		lenSS:           192,
		lenSSBytes:      192 / 8,
		lenChi:          16,
		lenChiBytes:     16 / 8,
		lenSkBytes:      31296,
		lenPkBytes:      15632,
		lenCtBytes:      15744,
		shake:           Shake256,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

func Frodo976SHAKE() (f FrodoKEM) {
	f = Frodo976AES()
	f.gen = f.genSHAKE128
	return
}

func Frodo1344AES() (f FrodoKEM) {
	f = FrodoKEM{
		errDistribution: []uint16{18286, 14320, 6876, 2023, 364, 40, 2},
		D:               16,
		q:               0,
		n:               1344,
		nBar:            8,
		mBar:            8,
		B:               4,
		lenSeedA:        128,
		lenSeedABytes:   128 / 8,
		lenZ:            128,
		lenZBytes:       128 / 8,
		lenMu:           256,
		lenMuBytes:      256 / 8,
		lenSeedSE:       256,
		lenSeedSEBytes:  256 / 8,
		lenS:            256,
		lenSBytes:       256 / 8,
		lenK:            256,
		lenKBytes:       256 / 8,
		lenPkh:          256,
		lenPkhBytes:     256 / 8,
		lenSS:           256,
		lenSSBytes:      256 / 8,
		lenChi:          16,
		lenChiBytes:     16 / 8,
		lenSkBytes:      43088,
		lenPkBytes:      21520,
		lenCtBytes:      21632,
		shake:           Shake256,
		rng:             cryptoRand,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return
}

func Frodo1344SHAKE() (f FrodoKEM) {
	f = Frodo1344AES()
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

func Shake128(msg []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum128(hash, msg)
	return
}

func Shake256(msg []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum256(hash, msg)
	return
}
