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

func logCompleted() {
	fmt.Printf("%v - Progress report: %v completed (%v in fly.)\n",
		time.Now().Format(time.Stamp), atomic.LoadInt64(&grandTotal), atomic.LoadInt32(&flying))
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
		ssDec, err := kem.Dencapsulate(sk, ct)
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
		time.Now().Format(time.Stamp), name, batchSize, elapsed.Seconds(),
		float64(batchSize)/elapsed.Seconds(), atomic.LoadInt32(&flying))
}

func soakTest() {
	maxGoProcs := runtime.NumCPU() - 1
	runtime.GOMAXPROCS(maxGoProcs)
	QtyPerSuite := 1_000_000
	batchSize := 1_000
	atomic.StoreInt32(&flying, 0)
	fmt.Printf("SoakTest: GenKey->Encaps->Decaps->DecapsFast\n"+
		" - %v cihper-variants\n - %v batch-size\n - %v in-total\n - %v goroutines-concurrency\n\n",
		len(frodo.Variants()), batchSize, QtyPerSuite*len(frodo.Variants()), maxGoProcs)
	for _, kem := range frodo.Variants() {
		for i := 0; i < QtyPerSuite/batchSize; i++ {
			for atomic.LoadInt32(&flying) >= 250 {
				time.Sleep(time.Second * 20)
				logCompleted()
				runtime.GC()
			}
			atomic.AddInt32(&flying, 1)
			go runOne(kem.Name(), batchSize, kem)
		}
	}
	for atomic.LoadInt32(&flying) != 0 {
		time.Sleep(time.Second * 5)
		logCompleted()
		runtime.GC()
	}
	println("Finished. Last status:")
	logCompleted()
}

func main() {
	soakTest()
}
