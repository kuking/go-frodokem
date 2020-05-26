//
// Checkout: https://github.com/Microsoft/PQCrypto-LWEKE
//
// copy this rndgen.c to the root folder of the PQCrypto-LWEKE project.
//
// add the following to the Makefile:
// +rndgen: rndgen.c $(AES_OBJS) $(AES_NI_OBJS)
// +       $(CC) $(CFLAGS) rndgen.c tests/rng.c $(LDFLAGS) -o rndgen
//
// Compile it with: $ make rndgen
// Generate file: $ cat KAT/PQCkemKAT_* | grep 'seed =' | awk '{print $3}' | sort | uniq | ./rndgen > PRE_GEN_RND_FROM_SEEDS.txt
//
// It would be complex to implement in Golang the ad-hoc random number generator used by the KAT tests.
// There are multiple reason for this, to name a couple: there is no AES ECB implementation in the Golang standard
// library due to security reasons (It might give the users a false sense of security.). Another important one is that
// the RNG relies on mangling the AES key scheme which is abstracted out by the Golang implementation.
//
// So a simpler approach it to pre-generate enough randomness for the given seeds, by utilising the original C code
// and save it into a file (PRE_GEN_RND_FROM_SEEDS.txt, in this folder.)
//
// You would probably never have to compile and use this program, unless the KAT files are updated with new seeds.
// In that situation occurs, it is likely the software maintainers would do it for you.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tests/rng.h"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int hexVal(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

int readHexLine(FILE *fp, unsigned char *buf, int maxLength) {
    int i = 0, ch, hex;
    buf[0] = 0;
    while ((ch = fgetc(fp)) != EOF && i >> 1 < maxLength) {
        if (ch == '\n') {
            break;
        }
        hex = hexVal(ch);
        if (hex == -1) {
            fprintf(stderr, "Unexpected non-hex char.");
            break;
        }
        if (i % 2 == 0) {
            buf[i >> 1] = hex << 4;
        } else {
            buf[i >> 1] |= hex;
        }
        i++;
    }
    return i >> 1;
}

void printHex(FILE *fp, unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        fprintf(fp, "%02X", buf[i]);
    }
}

int main() {
    int size;
    unsigned char seed[48];
    unsigned char rndBytes[256];
    while ((size = readHexLine(stdin, seed, sizeof(seed))) > 0) {
        randombytes_init(seed, NULL, 256);
        randombytes(rndBytes, sizeof(rndBytes));
        printHex(stdout, seed, size);
        printf(" = ");
        printHex(stdout, rndBytes, sizeof(rndBytes));
        printf("\n");
    }
}


