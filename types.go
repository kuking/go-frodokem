package go_frodokem

import (
	"crypto/aes"
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

	lenSkBytes int
	lenPkBytes int
	lenCtBytes int
	shake      func(msg []byte, digestLength int) []byte
	gen        func([]byte) [][]uint16
}

type PrivateKey struct {
}

type PublicKey struct {
}

//self.error_distribution = (9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1)
//self.T_chi = FrodoKEM.__cdf_zero_centred_symmetric(self.error_distribution)

func shake128(msg []byte, size int) (r []byte) {
	shake := sha3.NewCShake128([]byte{}, []byte{})
	shake.Write(msg)
	r = make([]byte, size)
	shake.Read(r)
	return
}

func AES128w16BytesOnly(key []byte, msg [16]byte) (r [16]byte) {
	r = [16]byte{}
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	b.Encrypt(r[:], msg[:])
	return r
}

func (k *FrodoKEM) genAES128(seedA []byte) (A [][]uint16) {
	A = make([][]uint16, k.n)
	for i := 0; i < k.n; i++ {
		A[i] = make([]uint16, k.n)
	}
	var b = [16]byte{}
	for i := 0; i < k.n; i++ {
		for j := 0; j < k.n; j += 8 {
			binary.LittleEndian.PutUint16(b[0:2], uint16(i))
			binary.LittleEndian.PutUint16(b[2:4], uint16(j))
			c := AES128w16BytesOnly(seedA, b)
			for l := 0; l < 8; l++ {
				A[i][j+l] = binary.LittleEndian.Uint16(c[l*2:(l+1)*2]) % k.q
			}

		}
	}
	return
}


func Frodo640AES() FrodoKEM {

	f := FrodoKEM{
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
		shake:           shake128,
	}
	f.tChi = cdfZeroCentredSymmetric(f.errDistribution)
	f.gen = f.genAES128
	return f
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