#!/usr/bin/python
"""
    Copyright (C) 2016 Minghui Liu
    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""
from aes import AES as AES

# NIST AES Test Cases
NIST_TESTS = [
    {
        'KEY': '0000000000000000000000000000000000000000000000000000000000000000',
        'PLAINTEXT': '014730f80ac625fe84f026c60bfd547d',
        'CIPHERTEXT': '5c9d844ed46f9885085e5d6a4f94c7d7'
    },
    {
        'KEY':'0000000000000000000000000000000000000000000000000000000000000000',
        'PLAINTEXT': '0b24af36193ce4665f2825d7b4749c98',
        'CIPHERTEXT': 'a9ff75bd7cf6613d3731c77c3b6d0c04'
    },
    {
        'KEY': '0000000000000000000000000000000000000000000000000000000000000000',
        'PLAINTEXT': '761c1fe41a18acf20d241650611d90f1',
        'CIPHERTEXT': '623a52fcea5d443e48d9181ab32c7421'
    },
    {
        'KEY': '0000000000000000000000000000000000000000000000000000000000000000',
        'PLAINTEXT': '8a560769d605868ad80d819bdba03771',
        'CIPHERTEXT': '38f2c7ae10612415d27ca190d27da8b4'
    },
    {
        'KEY': '0000000000000000000000000000000000000000000000000000000000000000',
        'PLAINTEXT': '91fbef2d15a97816060bee1feaa49afe',
        'CIPHERTEXT': '1bc704f1bce135ceb810341b216d7abe'
    },
    {
        'KEY': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        'PLAINTEXT': '00112233445566778899aabbccddeeff',
        'CIPHERTEXT': '8ea2b7ca516745bfeafc49904b496089'
    }
]

# Encryption test
for i, test in enumerate(NIST_TESTS):
    plaintext = AES.transpose(AES.hexStringToState(test['PLAINTEXT']))
    key = AES.hexStringToState(test['KEY'])
    ciphertext = AES.stateToHexString(AES.transpose(AES.aesEncrypt(plaintext, key)))
    assert ciphertext == test['CIPHERTEXT']
    print "  Encryption test case", i, "passed"

# Decryption test
for i, test in enumerate(NIST_TESTS):
    ciphertext = AES.transpose(AES.hexStringToState(test['CIPHERTEXT']))
    key = AES.hexStringToState(test['KEY'])
    plaintext = AES.stateToHexString(AES.transpose(AES.aesDecrypt(ciphertext, key)))
    assert plaintext == test['PLAINTEXT']
    print "  Decryption test case", i, "passed"
