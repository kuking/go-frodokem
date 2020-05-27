package go_frodokem

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ulikunitz/xz"
	"os"
	"regexp"
	"strconv"
	"testing"
)

type TestData struct {
	kem        *FrodoKEM
	filename   *string
	count      int64
	randomness []byte
	expPk      []byte
	expSk      []byte
	expCt      []byte
	expSs      []byte
}

func (td *TestData) clear() {
	td.kem = nil
	td.filename = nil
	td.count = -1
	td.randomness = nil
	td.expPk = nil
	td.expSk = nil
	td.expCt = nil
	td.expSs = nil
}

func (td *TestData) doTest(t *testing.T) {
	t.Parallel()
	nrng := NewNonRandomNG(td.randomness)
	td.kem.rng = nrng.rng
	pk, sk := td.kem.Keygen()
	if !bytes.Equal(td.expPk, pk) {
		t.Errorf("Expected PK not equal for file %v count %v\n[%v]\n[%v]\n",
			td.filename, td.count, hex.EncodeToString(td.expPk), hex.EncodeToString(pk))
	}
	if !bytes.Equal(td.expSk, sk) {
		t.Errorf("Expected SK not equal for file %v count %v\n[%v]\n[%v]\n",
			td.filename, td.count, hex.EncodeToString(td.expSk), hex.EncodeToString(sk))
	}
}

func processFile(t *testing.T, kemBuilder func() FrodoKEM, filename string) {
	randomness := loadPreGeneratedRandomnessFromSeeds(t)

	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	re := regexp.MustCompile(`^(\w*) = (\w*)$`)
	var td TestData

	reader, err := xz.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 90*1024), 90*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			td.clear()
			kem := kemBuilder()
			td.kem = &kem
			td.filename = &filename
		}

		match := re.FindStringSubmatch(line)
		if len(match) == 3 {
			if match[1] == "count" {
				td.count, err = strconv.ParseInt(match[2], 10, 32)
			}
			if match[1] == "seed" {
				td.randomness = randomness[match[2]]
			}
			if match[1] == "pk" {
				td.expPk, err = hex.DecodeString(match[2])
			}
			if match[1] == "sk" {
				td.expSk, err = hex.DecodeString(match[2])
			}
			if match[1] == "ct" {
				td.expCt, err = hex.DecodeString(match[2])
			}
			if match[1] == "ss" {
				td.expSs, err = hex.DecodeString(match[2])
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		if td.expSs != nil {
			td4Parallel := td
			t.Run(fmt.Sprintf("%v(%v)", filename, td4Parallel.count), td4Parallel.doTest)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestPQCkemKAT_19888_RSP(t *testing.T) {
	processFile(t, Frodo640AES, "KAT/PQCkemKAT_19888.rsp.xz")
}

func TestPQCkemKAT_19888_SHAKE_RSP(t *testing.T) {
	processFile(t, Frodo640SHAKE, "KAT/PQCkemKAT_19888_shake.rsp.xz")
}

func TestPQCkemKAT_31296_RSP(t *testing.T) {
	processFile(t, Frodo976AES, "KAT/PQCkemKAT_31296.rsp.xz")
}

func TestPQCkemKAT_31296_SHAKE_RSP(t *testing.T) {
	processFile(t, Frodo976SHAKE, "KAT/PQCkemKAT_31296_shake.rsp.xz")
}

func TestPQCkemKAT43088_RSP(t *testing.T) {
	processFile(t, Frodo1344AES, "KAT/PQCkemKAT_43088.rsp.xz")
}

func TestPQCkemKAT43088_SHAKE_RSP(t *testing.T) {
	processFile(t, Frodo1344SHAKE, "KAT/PQCkemKAT_43088_shake.rsp.xz")
}

func loadPreGeneratedRandomnessFromSeeds(t *testing.T) (result map[string][]byte) {
	result = make(map[string][]byte)
	file, err := os.Open("KAT/PRE_GEN_RND_FROM_SEEDS.txt.xz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	reader, err := xz.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`^(\w*) = (\w*)$`)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if len(match) == 3 {
			seed := match[1]
			randomness, err := hex.DecodeString(match[2])
			if err != nil {
				t.Error(err)
			}
			result[seed] = randomness
		} else {
			t.Error("pre generated randomness from seeds, file can't be parsed.")
		}
	}
	return
}

// -------------------------------------------------------------------------------------------------------------------

type NonRandomNG struct {
	data []byte
}

func NewNonRandomNG(seedData []byte) (dr NonRandomNG) {
	dr = NonRandomNG{data: seedData}
	return
}

func (dr *NonRandomNG) rng(target []byte) {
	copy(target, dr.data)
	dr.data = dr.data[len(target):]
}
