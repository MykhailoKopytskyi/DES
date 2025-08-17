# DES algorithm in Electronic Code Book mode in Java
A program was created out of interest to see how the real encryption algorithm works "under the hood". Java was used to implement the project, although almost any other programming language would fit well.
## Table of Contents  
- [Overview](#overview)
- [Installation](#installation)  
- [Usage](#usage)  
- [Resources](#resources)  

## Overview 
DES is a symmetric key encryption algorithm that was developed in the early 1970s by IBM. It was then submitted to the National Bureau of Standards (NBS) and its modified version became a Federal Infromation Processing Standard (FIPS). After that, the DES spread across the globe and was used as a standardised encryption algorithm.

## Installation
Do a git clone of the repository or download a zip file.

## Usage 
1. To encrypt the `pathToPlaintextFile` using `pathToKeyFile` and to have the ciphertext in `pathToCiphertextFile`, run: 
```
java Main -e pathToPlaintextFile pathToCiphertextFile pathToKeyFile
```
2. To decrypt the `pathToCiphertextFile` using `pathToKeyFile` and to have the plaintext in `pathToPlaintextFile`, run:
```
java Main -d `pathToCiphertextFile` `pathToPlaintextFile` `pathToKeyFile`
```

3. To generate a 64-bit key to be saved in `pathToKeyFile`, run:
```
java Main -g pathToKeyFile
```

## Resources
1. [The DES algorithm illustration](https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm)
2. [The DES description](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
