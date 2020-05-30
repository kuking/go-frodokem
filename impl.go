package go_frodokem

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func (k *FrodoKEM) Keygen() (pk []uint8, sk []uint8) {
	sSeedSEz := make([]byte, k.lenS/8+k.lenSeedSE/8+k.lenZ/8)
	k.rng(sSeedSEz) //	fmt.Println("randomness(", len(sSeedSEz), ")", strings.ToUpper(hex.EncodeToString(sSeedSEz)))
	s := sSeedSEz[0 : k.lenS/8]
	seedSE := sSeedSEz[k.lenS/8 : k.lenS/8+k.lenSeedSE/8] // fmt.Println("seedSE", hex.EncodeToString(seedSE))
	z := sSeedSEz[k.lenS/8+k.lenSeedSE/8 : k.lenS/8+k.lenSeedSE/8+k.lenZ/8]
	seedA := k.shake(z, k.lenSeedA/8) //	fmt.Println("seedA(", len(seedA), ")", strings.ToUpper(hex.EncodeToString(seedA)))
	A := k.gen(seedA)
	rBytesTmp := make([]byte, len(seedSE)+1)
	rBytesTmp[0] = 0x5f
	copy(rBytesTmp[1:], seedSE)
	rBytes := k.shake(rBytesTmp, 2*k.n*k.nBar*k.lenChi/8)       //fmt.Println("rBytes", len(rBytes), hex.EncodeToString(rBytes))
	r := unpackUint16(rBytes)                                   //fmt.Println("r(", len(r), ")", r)
	Stransposed := k.sampleMatrix(r[0:k.n*k.nBar], k.nBar, k.n) //fmt.Println("S^T", Stransposed)
	S := matrixTranspose(Stransposed)
	E := k.sampleMatrix(r[k.n*k.nBar:2*k.n*k.nBar], k.n, k.nBar)
	B := matrixAdd(matrixMulWithMod(A, S, k.q), E)
	b := k.pack(B) // fmt.Println("b", hex.EncodeToString(b))
	pk = append(seedA, b...)
	pkh := k.shake(pk, k.lenPkh/8) // fmt.Println("pkh", strings.ToUpper(hex.EncodeToString(pkh)))
	stb := make([]uint8, len(Stransposed)*len(Stransposed[0])*2)
	stbI := 0
	for i := 0; i < len(Stransposed); i++ {
		for j := 0; j < len(Stransposed[i]); j++ {
			stb[stbI] = uint8(Stransposed[i][j] & 0xff)
			stbI++
			stb[stbI] = uint8(Stransposed[i][j] >> 8)
			stbI++
		}
	}
	sk = append(s, seedA...)
	sk = append(sk, b...)
	sk = append(sk, stb...)
	sk = append(sk, pkh...)
	return
}

func (k *FrodoKEM) Encapsulate(pk []uint8) (ct []uint8, ssEnc []uint8, err error) {
	if len(pk) != k.lenSeedA/8+k.D*k.n*k.nBar/8 {
		err = errors.New("incorrect public key length")
	}
	seedA := pk[0 : k.lenSeedA/8]
	b := pk[k.lenSeedA/8:]
	mu := make([]uint8, k.lenMu/8)
	k.rng(mu)
	//fmt.Println("seedA", hex.EncodeToString(seedA))
	//fmt.Println("b", hex.EncodeToString(b))
	//fmt.Println("mu", hex.EncodeToString(mu))
	pkh := k.shake(pk, k.lenPkh/8) // fmt.Println("pkh", hex.EncodeToString(pkh))
	seedSE_k := k.shake(append(pkh, mu...), k.lenSeedSE/8+k.lenK/8)
	seedSE := seedSE_k[0 : k.lenSeedSE/8]
	_k := seedSE_k[k.lenSeedSE/8 : k.lenSeedSE/8+k.lenK/8]
	rBytesTmp := make([]byte, len(seedSE)+1)
	rBytesTmp[0] = 0x96
	copy(rBytesTmp[1:], seedSE)
	rBytes := k.shake(rBytesTmp, (2*k.mBar*k.n*k.mBar*k.mBar)*k.lenChi/8)
	r := unpackUint16(rBytes)
	Sprime := k.sampleMatrix(r[0:k.mBar*k.n], k.mBar, k.n)            // fmt.Println("S'", Sprime)
	Eprime := k.sampleMatrix(r[k.mBar*k.n:2*k.mBar*k.n], k.mBar, k.n) // fmt.Println("E'", Eprime)
	A := k.gen(seedA)
	Bprime := matrixAdd(matrixMulWithMod2(Sprime, A, k.q), Eprime)                            // fmt.Println("B'", Bprime)
	c1 := k.pack(Bprime)                                                                      // fmt.Println("c1", hex.EncodeToString(c1))
	Eprimeprime := k.sampleMatrix(r[2*k.mBar*k.n:2*k.mBar*k.n+k.mBar*k.nBar], k.mBar, k.nBar) // fmt.Println("E''", Eprimeprime)
	B := k.unpack(b, k.n, k.nBar)
	V := matrixAdd(matrixMulWithMod2(Sprime, B, k.q), Eprimeprime)
	muEncoded := k.encode(mu)

	//C := matrixAdd(V, unpackUint16(mu))

	fmt.Println(len(_k), len(c1), len(Eprimeprime), len(B), len(V), len(muEncoded))

	return
}

func (k *FrodoKEM) Dencapsulate(sk []uint8, ct []uint8) (ssDec []uint8, err error) {
	return
}

func matrixAdd(X [][]uint16, Y [][]int16) (R [][]uint16) {
	nrowsx := len(X)
	ncolsx := len(X[0])
	nrowsy := len(Y)
	ncolsy := len(Y[0])
	if nrowsx != nrowsy || ncolsx != ncolsy {
		panic("can't add these matrices")
	}
	R = make([][]uint16, nrowsx)
	for i := 0; i < nrowsx; i++ {
		R[i] = make([]uint16, ncolsx)
		for j := 0; j < ncolsx; j++ {
			R[i][j] = uint16(int(X[i][j]) + int(Y[i][j]))
		}
	}
	return
}

func matrixMulWithMod(X [][]uint16, Y [][]int16, q uint16) (R [][]uint16) {
	nrowsx := len(X)
	ncolsx := len(X[0])
	//nrowsy := len(y)
	ncolsy := len(Y[0])
	R = make([][]uint16, nrowsx)
	for i := 0; i < len(R); i++ {
		R[i] = make([]uint16, ncolsy)
	}
	for i := 0; i < nrowsx; i++ {
		for j := 0; j < ncolsy; j++ {
			for k := 0; k < ncolsx; k++ {
				R[i][j] += uint16(int32(X[i][k]) * int32(Y[k][j]))
			}
			if q != 0 {
				R[i][j] %= q
			}
		}
	}
	return
}

func matrixMulWithMod2(X [][]int16, Y [][]uint16, q uint16) (R [][]uint16) {
	nrowsx := len(X)
	ncolsx := len(X[0])
	//nrowsy := len(y)
	ncolsy := len(Y[0])
	R = make([][]uint16, nrowsx)
	for i := 0; i < len(R); i++ {
		R[i] = make([]uint16, ncolsy)
	}
	for i := 0; i < nrowsx; i++ {
		for j := 0; j < ncolsy; j++ {
			for k := 0; k < ncolsx; k++ {
				R[i][j] += uint16(int32(X[i][k]) * int32(Y[k][j]))
			}
			if q != 0 {
				R[i][j] %= q
			}
		}
	}
	return
}

func matrixTranspose(O [][]int16) (T [][]int16) {
	T = make([][]int16, len(O[0]))
	for x := 0; x < len(T); x++ {
		T[x] = make([]int16, len(O))
		for y := 0; y < len(O); y++ {
			T[x][y] = O[y][x]
		}
	}
	return
}

func unpackUint16(bytes []byte) (r []uint16) {
	r = make([]uint16, len(bytes)/2)
	j := 0
	for i := 0; i+1 < len(bytes); i += 2 {
		r[j] = binary.LittleEndian.Uint16(bytes[i : i+2])
		j++
	}
	return r
}

func (k *FrodoKEM) sample(r uint16) (e int16) {
	t := int(r >> 1)
	e = 0
	for z := 0; z < len(k.tChi)-1; z++ {
		if t > int(k.tChi[z]) {
			e += 1
		}
	}
	r0 := r % 2
	if r0 == 1 {
		e = -e
	}
	return
}

func (k *FrodoKEM) sampleMatrix(r []uint16, n1 int, n2 int) (E [][]int16) {
	E = make([][]int16, n1)
	for n := 0; n < n1; n++ {
		E[n] = make([]int16, n2)
	}
	for i := 0; i < n1; i++ {
		for j := 0; j < n2; j++ {
			E[i][j] = k.sample(r[i*n2+j])
		}
	}
	return E
}

// FrodoKEM specification, Algorithm 3: Frodo.Pack
func (k *FrodoKEM) pack(C [][]uint16) (r []byte) {
	rows := len(C)
	cols := len(C[0])
	r = make([]byte, k.D*rows*cols/8)
	var ri = 0
	var packed uint8
	var bits uint8
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			val := C[i][j]
			for b := 0; b < k.D; b++ {
				bit := uint16BitN(val, k.D-b-1)
				packed <<= 1
				packed |= bit
				bits++
				if bits == 8 {
					r[ri] = packed
					ri++
					packed = 0
					bits = 0
				}
			}
		}
	}
	if bits != 0 {
		r[ri] = packed
	}
	return r
}

// FrodoKEM specification, Algorithm 4: Frodo.Unpack
func (k *FrodoKEM) unpack(b []uint8, n1 int, n2 int) (C [][]uint16) {
	C = make([][]uint16, n1)
	for i := 0; i < n1; i++ {
		C[i] = make([]uint16, n2)
	}
	bIdx := 0
	BBit := 7
	for i := 0; i < n1; i++ {
		for j := 0; j < n2; j++ {
			for l := 0; l < k.D; l++ {
				bit := uint8BitN(b[bIdx], BBit)
				BBit--
				if BBit < 0 {
					BBit = 7
					bIdx++
				}
				C[i][j] <<= 1
				if bit > 0 {
					C[i][j] |= 1
				}
			}
		}
	}
	return
}

// FrodoKEM specification, Algorithm 1
func (k *FrodoKEM) encode(b []uint8) (K [][]uint16) {
	K = make([][]uint16, k.mBar)
	for i := 0; i < k.mBar; i++ {
		K[i] = make([]uint16, k.nBar)
	}
	multiplier := k.q
	if k.B > 0 {
		multiplier /= 2 << (k.B - 1)
	}
	bIdx := 0
	BBit := 0
	for i := 0; i < k.mBar; i++ {
		for j := 0; j < k.nBar; j++ {
			for l := 0; l < k.B; l++ {
				bit := uint8BitN(b[bIdx], BBit)
				fmt.Print(bit)
				if BBit++; BBit > 7 {
					BBit = 0
					bIdx++
				}
				if bit > 0 {
					K[i][j] |= 1 << l
				}
			}
			K[i][j] *= multiplier
		}
	}
	return
}

func uint16BitN(val uint16, i int) uint8 {
	return uint8((val >> i) & 1)
}
func uint8BitN(val uint8, i int) uint8 {
	return (val >> i) & 1
}

func (k *FrodoKEM) OverrideRng(newRng func([]byte)) {
	k.rng = newRng
}
