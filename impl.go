package go_frodokem

import (
	"crypto/rand"
	"encoding/binary"
)

func cryptoFillWithRandImpl(target []byte) {
	n, err := rand.Read(target)
	if err != nil {
		panic(err)
	}
	if len(target) != n {
		panic("could not generate enough randomness")
	}
}

var RandomFill = cryptoFillWithRandImpl

func (k *FrodoKEM) Keygen() (pk []uint8, sk []uint8) {
	sSeedSEz := make([]byte, k.lenSBytes+k.lenSeedSEBytes+k.lenZBytes)
	RandomFill(sSeedSEz) //	fmt.Println("randomness(", len(sSeedSEz), ")", strings.ToUpper(hex.EncodeToString(sSeedSEz)))
	s := sSeedSEz[0:k.lenSBytes]
	seedSE := sSeedSEz[k.lenSBytes : k.lenSBytes+k.lenSeedSEBytes] // fmt.Println("seedSE", hex.EncodeToString(seedSE))
	z := sSeedSEz[k.lenSBytes+k.lenSeedSEBytes : k.lenSBytes+k.lenSeedSEBytes+k.lenZBytes]
	seedA := k.shake(z, k.lenSeedABytes) //	fmt.Println("seedA(", len(seedA), ")", strings.ToUpper(hex.EncodeToString(seedA)))
	A := k.gen(seedA)
	rBytesTmp := make([]byte, len(seedSE)+1)
	rBytesTmp[0] = 0x5f
	copy(rBytesTmp[1:], seedSE)
	rBytes := k.shake(rBytesTmp, 2*k.n*k.nBar*k.lenChiBytes)    //fmt.Println("rBytes", len(rBytes), hex.EncodeToString(rBytes))
	r := unpackUint16(rBytes)                                   //fmt.Println("r(", len(r), ")", r)
	Stransposed := k.sampleMatrix(r[0:k.n*k.nBar], k.nBar, k.n) //fmt.Println("S^T", Stransposed)
	S := matrixTranspose(Stransposed)
	E := k.sampleMatrix(r[k.n*k.nBar:2*k.n*k.nBar], k.n, k.nBar)
	B := matrixAdd(matrixMulWithMod(A, S, k.q), E)
	b := k.pack(B) // fmt.Println("b", hex.EncodeToString(b))
	pk = append(seedA, b...)
	pkh := k.shake(pk, k.lenPkhBytes) // fmt.Println("pkh", strings.ToUpper(hex.EncodeToString(pkh)))
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

// Algorithm 3: Frodo.Pack
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
				bit := bitn(val, k.D-b-1)
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

func bitn(val uint16, i int) uint8 {
	return uint8((val >> i) & 1)
}
