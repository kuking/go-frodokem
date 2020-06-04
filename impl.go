package go_frodokem

import (
	"encoding/binary"
	"errors"
	"math"
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
	B := matrixAddWithMod(matrixMulWithMod(A, S, k.q), E, k.q)
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
		return
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
	Bprime := matrixAddWithMod(matrixMulWithMod2(Sprime, A, k.q), Eprime, k.q)                // fmt.Println("B'", Bprime)
	c1 := k.pack(Bprime)                                                                      // fmt.Println("c1", hex.EncodeToString(c1))
	Eprimeprime := k.sampleMatrix(r[2*k.mBar*k.n:2*k.mBar*k.n+k.mBar*k.nBar], k.mBar, k.nBar) // fmt.Println("E''", Eprimeprime)
	B := k.unpack(b, k.n, k.nBar)
	V := matrixAddWithMod(matrixMulWithMod2(Sprime, B, k.q), Eprimeprime, k.q)
	C := uMatrixAdd(V, k.encode(mu), k.q)
	c2 := k.pack(C) // 	fmt.Println("c2", hex.EncodeToString(c2))
	ct = append(c1, c2...)
	ssEnc = k.shake(append(ct, _k...), k.lenSS/8)
	if len(ct) != k.lenCtBytes {
		err = errors.New("ct length is not correct")
	}
	if len(ssEnc) != k.lenSS/8 {
		err = errors.New("ssEnc length is not correct")
	}
	return
}

func (k *FrodoKEM) Dencapsulate(sk []uint8, ct []uint8) (ssDec []uint8, err error) {
	if len(ct) != k.lenCtBytes {
		err = errors.New("incorrect cipher length")
		return
	}
	if len(sk) != k.lenSkBytes {
		err = errors.New("incorrect secret key length")
		return
	}

	c1, c2 := k.unwrapCt(ct)
	s, seedA, b, Stransposed, pkh := k.unwrapSk(sk)
	S := matrixTranspose(Stransposed)
	Bprime := k.unpack(c1, k.mBar, k.n)
	C := k.unpack(c2, k.mBar, k.nBar)
	BprimeS := matrixMulWithMod(Bprime, S, k.q)
	M := matrixSubWithMod(C, BprimeS, k.q)
	muPrime := k.decode(M) // fmt.Println("mu'", hex.EncodeToString(muPrime))

	seedSEprime_kprime := k.shake(append(pkh, muPrime...), k.lenSeedSE/8+k.lenK/8)
	seedSEprime := seedSEprime_kprime[0 : k.lenSeedSE/8] //	fmt.Println("seedSE'", hex.EncodeToString(seedSEprime))
	kprime := seedSEprime_kprime[k.lenSeedSE/8:]         //	fmt.Println("k'", hex.EncodeToString(kprime))

	rBytesTmp := make([]byte, len(seedSEprime)+1)
	rBytesTmp[0] = 0x96
	copy(rBytesTmp[1:], seedSEprime)
	rBytes := k.shake(rBytesTmp, (2*k.mBar*k.n+k.mBar*k.mBar)*k.lenChi/8)
	r := unpackUint16(rBytes) // fmt.Println("r", r)
	Sprime := k.sampleMatrix(r[0:k.mBar*k.n], k.mBar, k.n)
	Eprime := k.sampleMatrix(r[k.mBar*k.n:2*k.mBar*k.n], k.mBar, k.n)
	A := k.gen(seedA)
	Bprimeprime := matrixAddWithMod(matrixMulWithMod2(Sprime, A, k.q), Eprime, k.q)
	Eprimeprime := k.sampleMatrix(r[2*k.mBar*k.n:2*k.mBar*k.n+k.mBar*k.nBar], k.mBar, k.nBar)
	B := k.unpack(b, k.n, k.nBar)
	V := matrixAddWithMod(matrixMulWithMod2(Sprime, B, k.q), Eprimeprime, k.q)
	Cprime := uMatrixAdd(V, k.encode(muPrime), k.q)

	bothC := append(c1, c2...)
	if uint16Equals(Bprime, Bprimeprime) && uint16Equals(C, Cprime) {
		ssDec = k.shake(append(bothC, kprime...), k.lenSS/8)
	} else {
		ssDec = k.shake(append(bothC, s...), k.lenSS/8)
	}
	return
}

func uint16Equals(a [][]uint16, b [][]uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := 0; j < len(a[i]); j++ {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func (k *FrodoKEM) unwrapCt(ct []uint8) (c1 []uint8, c2 []uint8) {
	ofs := 0
	len := k.mBar * k.n * k.D / 8
	c1 = ct[ofs:len] // fmt.Println("c1", hex.EncodeToString(c1))
	ofs += len
	len = k.mBar * k.mBar * k.D / 8
	c2 = ct[ofs : ofs+len] // fmt.Println("c2", hex.EncodeToString(c2))
	return
}

func (k *FrodoKEM) unwrapSk(sk []uint8) (s []uint8, seedA []uint8, b []uint8, Stransposed [][]int16, pkh []uint8) {
	ofs := 0
	len := k.lenS / 8
	s = sk[ofs:len] // fmt.Println("s", hex.EncodeToString(s))
	ofs += len
	len = k.lenSeedA / 8
	seedA = sk[ofs : ofs+len] // fmt.Println("seedA", hex.EncodeToString(seedA))
	ofs += len
	len = k.D * k.n * k.nBar / 8
	b = sk[ofs : ofs+len] // fmt.Println("b", hex.EncodeToString(b))

	ofs += len
	len = k.n * k.nBar * 2
	Sbytes := sk[ofs : ofs+len]

	idx := 0
	Stransposed = make([][]int16, k.nBar)
	for i := 0; i < k.nBar; i++ {
		Stransposed[i] = make([]int16, k.n)
		for j := 0; j < k.n; j++ {
			Stransposed[i][j] = int16(Sbytes[idx])
			idx++
			Stransposed[i][j] |= int16(Sbytes[idx]) << 8
			idx++
		}
	}
	// fmt.Println("S^T", Stransposed)

	ofs += len
	len = k.lenPkh / 8
	pkh = sk[ofs : ofs+len] // fmt.Println("pkh", hex.EncodeToString(pkh))

	return
}

func matrixAddWithMod(X [][]uint16, Y [][]int16, q uint16) (R [][]uint16) {
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
			if q != 0 {
				R[i][j] %= q
			}
		}
	}
	return
}

func uMatrixAdd(X [][]uint16, Y [][]uint16, q uint16) (R [][]uint16) {
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
			if q != 0 {
				R[i][j] %= q
			}
		}
	}
	return
}

func matrixSubWithMod(X [][]uint16, Y [][]uint16, q uint16) (R [][]uint16) {
	nrowsx := len(X)
	ncolsx := len(X[0])
	nrowsy := len(Y)
	ncolsy := len(Y[0])
	if nrowsx != nrowsy || ncolsx != ncolsy {
		panic("can't sub these matrices")
	}
	R = make([][]uint16, nrowsx)
	for i := 0; i < nrowsx; i++ {
		R[i] = make([]uint16, ncolsx)
		for j := 0; j < ncolsx; j++ {
			R[i][j] = uint16(int(X[i][j]) - int(Y[i][j]))
			if q != 0 {
				R[i][j] %= q
			}
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
	multiplier := int(k.q)
	if multiplier == 0 {
		multiplier = 65536
	}
	if k.B > 0 {
		multiplier /= 2 << (k.B - 1)
	}
	bIdx := 0
	BBit := 0
	for i := 0; i < k.mBar; i++ {
		for j := 0; j < k.nBar; j++ {
			for l := 0; l < k.B; l++ {
				bit := uint8BitN(b[bIdx], BBit)
				if BBit++; BBit > 7 {
					BBit = 0
					bIdx++
				}
				if bit > 0 {
					K[i][j] |= 1 << l
				}
			}
			K[i][j] *= uint16(multiplier)
		}
	}
	return
}

// FrodoKEM specification, Algorithm 2
func (k *FrodoKEM) decode(K [][]uint16) (b []uint8) {
	b = make([]uint8, k.B*k.mBar*k.nBar/8)
	fixedQ := float64(k.q)
	if k.q == 0 {
		fixedQ = float64(65535)
	}
	twoPowerB := int32(2 << (k.B - 1))
	twoPowerBf := float64(int(2 << (k.B - 1)))
	bIdx := 0
	BBit := 0
	for i := 0; i < k.mBar; i++ {
		for j := 0; j < k.nBar; j++ {
			tmp := uint8(int32(math.Round(float64(K[i][j])*twoPowerBf/fixedQ)) % twoPowerB) //FIXME: please do this better
			for l := 0; l < k.B; l++ {
				bit := uint8BitN(tmp, l)
				if bit == 1 {
					b[bIdx] = uint8setBitN(b[bIdx], BBit)
				}
				BBit++
				if BBit == 8 {
					bIdx++
					BBit = 0
				}
			}
		}
	}
	return
}

func uint8setBitN(val uint8, i int) uint8 {
	return val | (1 << i)
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
