# FrodoKEM in Golang 
Golang implementation of FrodoKEM: a Practical quantum-secure key encapsulation from generic lattices (https://frodokem.org).
This implementation passes all KAT tests from the reference specification for all defined key sizes (640 / 976 / 1344) and variants (AES / SHAKE).

## API
There is a demo app that uses every method in the API. i.e. methods for listing variants, for creating key pairs,
encapsulating & dencapsulating kems, auxiliary methods reporting cipher-text length, key-length, variant name, etc. 
You can find it here: [demo.go](mains/demo/demo.go). The built binary will be placed in `bin/demo` (use `make build` to 
generate it).

You can also read the documentation using `go doc -all` in this package, or look at [impl.go](impl.go) and 
[types.go](types.go).

_Complete usage Snippet:_
```go
import frodo "github.com/kuking/go-frodokem"

kem := frodo.Frodo640AES()
pk, sk := kem.Keygen()                // public-key, secret-key
ct, ssEnc, _ := kem.Encapsulate(pk)   // cipher-text, shared-secret
ssDec, _ := kem.Dencapsulate(sk, ct)  // recovered shared-secret
// ssEnc == ssDec
```

For a full key agreement example, see [agreement_test.go](agreement_test.go).
 
#### Note on Concurrency
This library is stateless. A FrodoKEM struct (as returned by i.e. `frodo.Frodo640AES()`) can be used concurrently.
Keys are immutable `[]byte` and they can be shared between concurrent goroutines.

##  Author
Eduardo E.S. Riccardi, you can contact me via [linkedin](https://uk.linkedin.com/in/kukino), or you could find my email
address [here](https://kukino.uk/ed@kukino.uk.pub).

## Releases

v1.0.1 - 25 June 2020 - Fixed a possible timing attack [#2](https://github.com/kuking/go-frodokem/issues/2)

v1.0.0 - 10 June 2020 - Feature complete.

## Pending
- implement optimisations with SIMD instructions

