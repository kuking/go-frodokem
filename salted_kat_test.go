package go_frodokem

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

// The salted FrodoKEM known-answer tests are the .rsp files of the reference
// implementation (github.com/microsoft/PQCrypto-LWEKE, FrodoKEM/KAT),
// compressed with xz. Each entry gives a 48-byte seed for the NIST AES-256
// CTR DRBG; the key pair, ciphertext and shared secret follow from it.

// nistDRBG is the AES-256 CTR DRBG of the NIST PQC known-answer test
// harness (rng.c), without personalization and without reseeding. It is only
// for reproducing test vectors.
type nistDRBG struct {
	key [32]byte
	v   [16]byte
}

func newNistDRBG(seed []byte) *nistDRBG {
	if len(seed) != 48 {
		panic("the DRBG seed must be 48 bytes")
	}
	d := &nistDRBG{}
	d.update(seed)
	return d
}

func (d *nistDRBG) block(out []byte) {
	for i := 15; i >= 0; i-- {
		d.v[i]++
		if d.v[i] != 0 {
			break
		}
	}
	c, err := aes.NewCipher(d.key[:])
	if err != nil {
		panic(err)
	}
	c.Encrypt(out, d.v[:])
}

func (d *nistDRBG) update(provided []byte) {
	var temp [48]byte
	for i := 0; i < 3; i++ {
		d.block(temp[16*i : 16*i+16])
	}
	for i := range provided {
		temp[i] ^= provided[i]
	}
	copy(d.key[:], temp[:32])
	copy(d.v[:], temp[32:])
}

// rng fills target the way randombytes() does: whole blocks, then an update.
func (d *nistDRBG) rng(target []byte) {
	var block [16]byte
	for off := 0; off < len(target); off += 16 {
		d.block(block[:])
		copy(target[off:], block[:])
	}
	d.update(nil)
}

// The first vector of the NIST harness itself: seeding the DRBG with the
// bytes 0..47 and drawing 48 bytes gives the seed of entry 0 of every .rsp
// file.
func TestNistDRBGFirstSeed(t *testing.T) {
	entropy := make([]byte, 48)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	got := make([]byte, 48)
	newNistDRBG(entropy).rng(got)
	const want = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
	if strings.ToUpper(hex.EncodeToString(got)) != want {
		t.Fatalf("first DRBG output is %X, want %s", got, want)
	}
}

type saltedKAT struct {
	count          string
	seed           []byte
	pk, sk, ct, ss []byte
}

func readSaltedKATs(t *testing.T, filename string) (kats []saltedKAT) {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := xz.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var cur saltedKAT
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 128*1024), 128*1024)
	for scanner.Scan() {
		parts := strings.SplitN(strings.TrimSpace(scanner.Text()), " = ", 2)
		if len(parts) != 2 {
			continue
		}
		name, value := parts[0], parts[1]
		if name == "count" {
			cur = saltedKAT{count: value}
			continue
		}
		data, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("%s count %s %s: %v", filename, cur.count, name, err)
		}
		switch name {
		case "seed":
			cur.seed = data
		case "pk":
			cur.pk = data
		case "sk":
			cur.sk = data
		case "ct":
			cur.ct = data
		case "ss":
			cur.ss = data
			kats = append(kats, cur)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(kats) != saltedKATEntries {
		t.Fatalf("%s holds %d test vectors, want %d", filename, len(kats), saltedKATEntries)
	}
	for _, kat := range kats {
		if len(kat.seed) != 48 || len(kat.pk) == 0 || len(kat.sk) == 0 || len(kat.ct) == 0 || len(kat.ss) == 0 {
			t.Fatalf("%s count %s: a field is missing", filename, kat.count)
		}
	}
	return
}

// Every .rsp file of the reference implementation has this many entries.
const saltedKATEntries = 100

func runSaltedKATs(t *testing.T, kemBuilder func() FrodoKEM, filename string) {
	t.Parallel()
	for _, kat := range readSaltedKATs(t, filename) {
		kat := kat
		t.Run(fmt.Sprintf("count=%s", kat.count), func(t *testing.T) {
			t.Parallel()
			kem := kemBuilder()
			kem.OverrideRng(newNistDRBG(kat.seed).rng)
			pk, sk := kem.Keygen()
			if !bytes.Equal(pk, kat.pk) {
				t.Fatal("public key differs from the test vector")
			}
			if !bytes.Equal(sk, kat.sk) {
				t.Fatal("secret key differs from the test vector")
			}
			ct, ssEnc, err := kem.Encapsulate(pk)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ct, kat.ct) {
				t.Fatal("ciphertext differs from the test vector")
			}
			if !bytes.Equal(ssEnc, kat.ss) {
				t.Fatal("encapsulated shared secret differs from the test vector")
			}
			ssDec, err := kem.Dencapsulate(kat.sk, kat.ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ssDec, kat.ss) {
				t.Fatal("decapsulated shared secret differs from the test vector")
			}
		})
	}
}

func TestSaltedKAT_640_AES(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo640AES, "KAT/salted/PQCkemKAT_19888.rsp.xz")
}

func TestSaltedKAT_640_SHAKE(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo640SHAKE, "KAT/salted/PQCkemKAT_19888_shake.rsp.xz")
}

func TestSaltedKAT_976_AES(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo976AES, "KAT/salted/PQCkemKAT_31296.rsp.xz")
}

func TestSaltedKAT_976_SHAKE(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo976SHAKE, "KAT/salted/PQCkemKAT_31296_shake.rsp.xz")
}

func TestSaltedKAT_1344_AES(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo1344AES, "KAT/salted/PQCkemKAT_43088.rsp.xz")
}

func TestSaltedKAT_1344_SHAKE(t *testing.T) {
	runSaltedKATs(t, SaltedFrodo1344SHAKE, "KAT/salted/PQCkemKAT_43088_shake.rsp.xz")
}

// A salted ciphertext is the ephemeral one followed by the salt, and nothing
// else about the sizes changes.
func TestSaltedSizes(t *testing.T) {
	pairs := []struct {
		salted, ephemeral FrodoKEM
	}{
		{SaltedFrodo640AES(), Frodo640AES()}, {SaltedFrodo640SHAKE(), Frodo640SHAKE()},
		{SaltedFrodo976AES(), Frodo976AES()}, {SaltedFrodo976SHAKE(), Frodo976SHAKE()},
		{SaltedFrodo1344AES(), Frodo1344AES()}, {SaltedFrodo1344SHAKE(), Frodo1344SHAKE()},
	}
	for _, p := range pairs {
		s, e := p.salted, p.ephemeral
		if s.PublicKeyLen() != e.PublicKeyLen() || s.SecretKeyLen() != e.SecretKeyLen() || s.SharedSecretLen() != e.SharedSecretLen() {
			t.Errorf("%s: key or shared secret sizes differ from %s", s.Name(), e.Name())
		}
		if got, want := s.CipherTextLen(), e.CipherTextLen()+2*e.SharedSecretLen(); got != want {
			t.Errorf("%s: ciphertext is %d bytes, want %d", s.Name(), got, want)
		}
	}
}

// A ciphertext that was changed anywhere, the salt included, must be rejected
// implicitly: the shared secret is the hash of the whole changed ciphertext
// followed by the secret value s, which is the first part of the secret key.
func TestSaltedImplicitRejection(t *testing.T) {
	for _, kem := range []FrodoKEM{SaltedFrodo640SHAKE(), SaltedFrodo640AES()} {
		pk, sk := kem.Keygen()
		ct, ss, err := kem.Encapsulate(pk)
		if err != nil {
			t.Fatal(err)
		}
		s := sk[:kem.SharedSecretLen()]
		for _, at := range []struct {
			name  string
			index int
		}{
			{"first byte of c1", 0},
			{"last byte of the salt", len(ct) - 1},
			{"first byte of the salt", len(ct) - 2*kem.SharedSecretLen()},
		} {
			changed := append([]byte{}, ct...)
			changed[at.index] ^= 1
			got, err := kem.Dencapsulate(sk, changed)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, ss) {
				t.Errorf("%s, %s changed: the shared secret did not change", kem.Name(), at.name)
			}
			if want := kem.shake(append(append([]byte{}, changed...), s...), kem.SharedSecretLen()); !bytes.Equal(got, want) {
				t.Errorf("%s, %s changed: the shared secret is not the hash of the changed ciphertext and s", kem.Name(), at.name)
			}
		}
	}
}
