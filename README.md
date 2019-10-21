# pyAES
A very readable Python implementation of Advanced Encryption Standard (AES)

# Introduction
This project is a programming project aiming to implement AES using python for learning pur- poses. The design goal of this project is to break down and implement AES in a way that makes studying the internals of AES easier. It was not designed for real world production use and will not have the same level of security or performance as libraries used in production.

# Implementation Details
This project is written in Python 2.7. It is strongly recommended that you run this project with Python 2.7 as you might get errors using Python 3.
This implementation uses 128-bit fixed block size and 256-bit fixed key size. It supports three modes of operation, Electronic Code Book(ECB), Cipher Block Chaining(CBC) and Output Feed- back (OFB). The use of ECB is strongly discouraged as it leaks information about the plain text. It is only included for experiment.
This project has a single file, aes.py, and a single class called AES that encompasses everything. Users need to instantiate an instance of the AES class with a key to do encryption or decryption. All AES round functions are written according to AES standard. Note that AES standard defined AES stable table using column major order. To make coding easier, a transpose function is written to convert state from column major to row order, which is easier to program in Python.

```
        def transpose(state):
            # return tranposed state
```

Since AES is a block cipher, inputs need to be padded so that its size is a multiple of AES block size. This implementation uses PKCS7 padding scheme to pad inputs.

```
        def appendPadding(bytes):
            # pad input to multiples of block size
        
        def stripPadding(bytes):
            # strip padding
```

Note that PKCS7 always pads input even if the input size is a multiple of block size, in which case PKCS7 appends an extra block to input.


# How to use this project
## Use the command line interface
This implementation comes with a command line interface for encrypting and decrypting files using password. To see help on how to use the command line interface, run python aes.py -h in terminal. To encrypt a file, run `python aes.py -e [inputfile] -o [outputfile]`. The output file name is optional and `[inputfile].aes` will be used if you don’t supply output file name. To decrypt a file, run `python aes.py -d [inputfile] -o [outputfile]`. The output file name is also optional here and `decrypted_[inputfile]` will be used by default. You will need to input a password to encrypt or decrypt a file.

## Use it in your project
To use this implementation, place aes.py in the same directory as your python project and include the AES class from aes.
```
        from aes import AES
```
Then your need to create a key. Note that the key must be in the form of a byte array (a list of integers between 0 and 255). You can create a random key using any random number generator or create a key from password using passwordToKey function in AES class.
```
        # generate key using random integer generator
        from random import randint
        key = [randint(0, 255) for _ in xrange(32)]

        # generate key using OS random string generator and convert to byte array
        import os
        key = map(ord, os.urandom(32))

        # generate key from password using passwordToKey function
        key = AES.passwordToKey("p@33w0rd")
```
Next you need to create an AES instance using the key you just generated.
```
        cipher = AES(key)
```
To encrypt a file, call your instance’s encrypt method and specify Mode of operation. Valid choices are "ECB", "CBC" and "OFB". For CBC mode and OFB mode, you can supply your own Initialization Vector. If you don’t then a random one will be generated.
```
        # encrypt using ECB Mode
        cipher.encrypt(plaintext, "ECB")

        # encrypt using CBC Mode and random IV
        cipher.encrypt(plaintext, "CBC")
        
        # encrypt using CBC Mode and suply your own IV
        myIV = map(ord, os.urandom(16))
        cipher.encrypt(plaintext, "CBC", iv=myIV)
```
To decrypt, use your instance’s decrypt method. # decrypt using CCB Mode
```
        cipher.decrypt(ciphertext, "CBC")
```
To encrypt or decrypt files, use your instance’s encryptFile and decryptFile methods. You need to specify an input file path. Output file name is optional as this implementation will give a default output name if you don’t supply one. Mode and IV are also optional and will default to CBC and a random generated IV.
```
        # encrypt test.pdf
        cipher.encryptFile("test.pdf")

        # encrypt to test.pdf.aes using CBC Mode and suply your own IV
        myIV = map(ord, os.urandom(16))
        cipher.encrypt("test.pdf", "test.pdf.aes", "CBC", iv=myIV)
        
        # decrypt test.pdf.aes
        # output file name will be decrypted_test.pdf
        cipher.decrypt("test.pdf.aes")
```

# Correctness
The correctness of this implementation is verified again NIST known AES test vectors. The tests are defined in correctness.py. To run the tests, open a terminal window and run `python correctness.py`.

# Performance
The speed of this implementation is measured against pyCrypto, a widely used Crypto library for Python. All tests are performed on the author’s laptop. Both encryption and decryption time for long randomly generated strings are measured for both implementations and compared. To run the performance test, run `python performance.py`.

![Performance Table](/table1.png)

As evident from Table 1 and 2, this implementation is significantly slower than pyCrypto, which is expected. Most of the operations in pyCrypto are vectorized to matrix multiplication, which makes the code run much faster.
