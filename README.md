# FrodoKEM in Golang 
(https://frodokem.org)

Golang implementation of FrodoKEM spec. Currently passing all KAT specs tests for all key sizes and variants (AES/Shake).
(https://github.com/microsoft/PQCrypto-LWEKE/tree/master/KAT).

## API
There is a demo app that uses every method in the API. i.e. methods for listing variants, for creating key pairs,
encapsulating/dencapsulating kems, auxiliary methods reporting cipher-text length, key-length, variant name, etc. 
You can see it here: [demo.go](mains/demo/demo.go). The built binary will be in `bin/demo` (use `make build` to 
generate it).

You can also read the documentation using `go doc -all` on this package, or look at [impl.go](impl.go) and [types.go](types.go).

_Minimal Example:_
```go
import frodo "github.com/kuking/go-frodokem"

kem := frodo.Frodo640AES()
pk, sk := kem.Keygen()                // public-key, secret-key
ct, ssEnc, _ := kem.Encapsulate(pk)   // cipher-text, shared-secret
ssDec, _ := kem.Dencapsulate(sk, ct)  // recovered shared-secret
// ssEnc == ssDec
```

### Pending
- implement optimisations with SIMD instructions

