package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

var (
	prefix   string
	suffix   string
	checksum bool
)

func main() {
	var (
		flagPrefix   = flag.String("prefix", "", "address prefix")
		flagSuffix   = flag.String("suffix", "", "address suffix")
		flagChecksum = flag.Bool("checksum", false, "compare prefix and suffix with checksum address")
		flagInf      = flag.Bool("inf", false, "Infinity find addresses")
		flagN        = flag.Int("n", 0, "Number of go routines")
	)
	flag.Parse()

	prefix = strings.TrimPrefix(*flagPrefix, "0x")
	suffix = *flagSuffix
	checksum = *flagChecksum
	inf := *flagInf
	n := *flagN

	if n <= 0 {
		n = runtime.NumCPU()
	}

	ch := make(chan *ecdsa.PrivateKey)

	for i := 0; i < n; i++ {
		go generate(ch)
	}

	fmt.Printf("address\t\t\t\t\t\tprivate key\n")
	for pk := range ch {
		fmt.Printf("%s\t%x\n",
			crypto.PubkeyToAddress(pk.PublicKey),
			crypto.FromECDSA(pk),
		)
		if !inf {
			break
		}
	}
}

func generate(ch chan<- *ecdsa.PrivateKey) {
	for {
		pk, _ := crypto.GenerateKey()

		addr := crypto.PubkeyToAddress(pk.PublicKey).String()
		addr = addr[2:]
		if !checksum {
			addr = strings.ToLower(addr)
		}

		if prefix != "" && !strings.HasPrefix(addr, prefix) {
			continue
		}
		if suffix != "" && !strings.HasSuffix(addr, suffix) {
			continue
		}

		ch <- pk
	}
}
