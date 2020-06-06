package main

import (
	"bytes"
	"fmt"
	frodo "github.com/kuking/go-frodokem"
	"runtime"
	"sync/atomic"
	"time"
)

var flying int32
var grandTotal int64

func suites() map[string]frodo.FrodoKEM {
	return map[string]frodo.FrodoKEM{
		"640-AES":    frodo.Frodo640AES(),
		"976-AES":    frodo.Frodo976AES(),
		"1344-AES":   frodo.Frodo1344AES(),
		"640-SHAKE":  frodo.Frodo640SHAKE(),
		"976-SHAKE":  frodo.Frodo976SHAKE(),
		"1344-SHAKE": frodo.Frodo1344SHAKE(),
	}
}

func logCompleted() {
	fmt.Printf("%v - %v completed (%v in fly.)\n",
		time.Now().Format(time.RFC822), atomic.LoadInt64(&grandTotal), atomic.LoadInt32(&flying))
}

func runOne(name string, batchSize int, kem frodo.FrodoKEM) {
	start := time.Now()
	for i := 0; i < batchSize; i++ {
		//fmt.Printf("%v#%v\n", name, i)
		pk, sk := kem.Keygen()
		ct, ssEnc, err := kem.Encapsulate(pk)
		if err != nil {
			panic(err)
		}
		ssDec, err := kem.DencapsulateFast(sk, ct)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(ssEnc, ssDec) {
			panic("ssEnc, ssDec not equal")
		}
	}
	elapsed := time.Since(start)
	atomic.AddInt64(&grandTotal, int64(batchSize))
	atomic.AddInt32(&flying, -1)
	fmt.Printf("%v - %v batch of %v completed in %2.2fs or %2.2f/s (%v in fly.).\n",
		time.Now().Format(time.RFC822), name, batchSize, elapsed.Seconds(),
		float64(batchSize)/elapsed.Seconds(), atomic.LoadInt32(&flying))
}


func soakTest() {
	maxGoProcs := runtime.NumCPU() - 1
	runtime.GOMAXPROCS(maxGoProcs)
	QtyPerSuite := 1_000_000
	batchSize := 1_000

	fmt.Printf("SoakTest, GenKey->Encaps->Decaps->DecapsFast (%v cihper-variants, %v batch-size, %v in total) ...\n",
		len(suites()), batchSize, QtyPerSuite*len(suites()))
	fmt.Printf("Running %v goroutines concurrently\n", maxGoProcs)
	flying = 0
	for name, kem := range suites() {
		for i := 0; i < QtyPerSuite/batchSize; i++ {
			for ; atomic.LoadInt32(&flying) >= 100; {
				time.Sleep(time.Second * 10)
				logCompleted()
				runtime.GC()
			}
			atomic.AddInt32(&flying, 1)
			go runOne(name, batchSize, kem)
		}
	}
	for ; atomic.LoadInt32(&flying) != 0; {
		time.Sleep(time.Second * 10)
		logCompleted()
		runtime.GC()
	}
	println("Finished.", atomic.LoadInt64(&grandTotal))
}

func main() {
	soakTest()
}
