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
from aes import AES as myAES
from Crypto.Cipher import AES
from Crypto import Random
from random import choice
from string import lowercase
import time

# Encryption
for n in [2**16, 2**18, 2**20]:
    for pymode, mode in [(AES.MODE_ECB, "ECB"), (AES.MODE_CBC, "CBC"), (AES.MODE_OFB, "OFB")]:
        ## pyCrypto
        text = ''.join(choice(lowercase) for _ in xrange(n))
        print "Size:", n, "bytes,", "Mode:", mode
        key = b'1234567890a0987654321b1234567890'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, pymode, iv)
        # encryption
        start = time.time()
        msg = cipher.encrypt(text)
        end = time.time()
        print "pyCrypto encrypt:", end - start
        # decryption
        start = time.time()
        pln = cipher.decrypt(msg)
        end = time.time()
        print "pyCrypto decrypt:", end - start

        ## this implementation
        key = map(ord, key)
        text = map(ord, text)
        iv = map(ord, iv)
        aes = myAES(key)
        # encryption
        start = time.time()
        ciphertext = aes.encrypt(text, mode, iv)
        end = time.time()
        print "myAES encrypt:", end - start
        # decryption
        start = time.time()
        plaintext = aes.decrypt(ciphertext, mode)
        end = time.time()
        print "myAES decrypt:", end - start
