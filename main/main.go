package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	frodo "github.com/kuking/go-frodokem"
)

var randoms = make([][]byte, 0)

func deterministicRandom(target []byte) {
	for _, r := range randoms {
		if len(r) == len(target) {
			copy(target, r)
			return
		}
	}
	panic("not deterministic-randomness -- check the implementation")
}

func addARandom(hexs string) {
	r, _ := hex.DecodeString(hexs)
	randoms = append(randoms, r)
}

func main_for_debug() {
	//seed := "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
	expSS, _ := hex.DecodeString("594DE84473B3408E35F6C4D1F2F2EC3B56D2DDA96FA23496")

	addARandom("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47")
	addARandom("33B3C07507E4201748494D832B6EE2A6")
	addARandom("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A")
	addARandom("EB4A7C66EF4EBA2DDB38C88D8BC706B1D639002198172A7B")
	addARandom("7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E4792F267AAFA3F87CA60D01CB54F29202A3E784CCB7EBCDCFD45542B7F6AF77874")
	addARandom("8BF0F459F0FB3EA8D32764C259AE631178976BAF3683D33383188A65A4C2449B")

	//fkem := frodo.Frodo640AES()
	//fkem := frodo.Frodo640SHAKE()
	fkem := frodo.Frodo976AES()
	fkem.OverrideRng(deterministicRandom)
	pk, sk := fkem.Keygen()
	fmt.Println()
	fmt.Println("pk", hex.EncodeToString(pk))
	fmt.Println()
	fmt.Println("sk", hex.EncodeToString(sk))

	ct, ssEnc, err := fkem.Encapsulate(pk)
	if err != nil {
		panic(err)
	}
	//fmt.Println("ct", hex.EncodeToString(ct))
	fmt.Println("ssEnc", hex.EncodeToString(ssEnc))

	if !bytes.Equal(ssEnc, expSS) {
		panic("encapsulate not what expected")
	}

	ssDec, err := fkem.Dencapsulate(sk, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println("ssDec", hex.EncodeToString(ssDec))

	if !bytes.Equal(ssEnc, ssDec) {
		panic("encapsulate -> dencapsulate didn't work")
	}

}
