# Introduction

AES-128, AES-192, and AES-256 algorithm specification.

# How to compile

OS: macOS M2
Compiler: gcc

aes128:
```bash
cd src
gcc aes128.c
./a.out
```

aes192:
```bash
cd src
gcc aes192.c
./a.out
```

aes256:
```bash
cd src
gcc aes256.c
./a.out
```

# Directory

- src: Contains the AES code.

- benchmark: Measures the cycle count for AES-128, AES-192, and AES-256 on macOS M2.

- debug: Allows verification of roundkey and state changes during key expansion and cipher operations.
