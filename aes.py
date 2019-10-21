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
import hashlib, os
from copy import copy

import sys, os, getopt, getpass

class AES:
    ## Some useful tables

    # The Rijndael S-Box
    sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
            ]
    # Inverse of Rijndael's S-Box
    sboxInv = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
            ]
    # Rijndael Rcon table
    rcon = [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
            ]

    ## Primitives

    # XOR each byte of roundKey with the state table
    # Caution: AES standard state is column major matrix so we have to transpose the roundKey
    # the inverse opearation of this function is itself
    @staticmethod
    def addRoundKey(state, roundKey):
        roundKey = AES.transpose(roundKey)
        for c in xrange(4):
            for r in xrange(4):
                state[r*4+c] = state[r*4+c] ^ roundKey[r*4+c]

    # substitute each byte in state table with sbox look up
    @staticmethod
    def subBytes(state):
        for i in range(len(state)):
            state[i] = AES.sbox[state[i]]

    # inverse subBytes using inverse sbox
    @staticmethod
    def subBytesInv(state):
        for i in range(len(state)):
            state[i] = AES.sboxInv[state[i]]

    # shift word n bytes to the left, a negative n with shift to the right
    @staticmethod
    def rotate(word, n):
        return word[n:] + word[:n]

    # iterate over each row in state table
    # and shift the bytes to the LEFT by row number
    @staticmethod
    def shiftRows(state):
        for i in xrange(4):
            state[i*4:i*4+4] = AES.rotate(state[i*4:i*4+4], i)

    # Inverse operation of shiftRows
    @staticmethod
    def shiftRowsInv(state):
        for i in xrange(4):
            state[i*4:i*4+4] = AES.rotate(state[i*4:i*4+4], -i)

    # Galois Multiplication
    # Algorithm from 
    # https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
    @staticmethod
    def galoisMult(a, b):
        p = 0
        hiBitSet = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hiBitSet = a & 0x80
            a <<= 1
            if hiBitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    # mix a single column
    @staticmethod
    def mixColumn(column):
        temp = copy(column)
        column[0] = AES.galoisMult(temp[0],2) ^ AES.galoisMult(temp[3],1) ^ AES.galoisMult(temp[2],1) ^ AES.galoisMult(temp[1],3)
        column[1] = AES.galoisMult(temp[1],2) ^ AES.galoisMult(temp[0],1) ^ AES.galoisMult(temp[3],1) ^ AES.galoisMult(temp[2],3)
        column[2] = AES.galoisMult(temp[2],2) ^ AES.galoisMult(temp[1],1) ^ AES.galoisMult(temp[0],1) ^ AES.galoisMult(temp[3],3)
        column[3] = AES.galoisMult(temp[3],2) ^ AES.galoisMult(temp[2],1) ^ AES.galoisMult(temp[1],1) ^ AES.galoisMult(temp[0],3)

    # inverse of mixColumn
    @staticmethod
    def mixColumnInv(column):
        temp = copy(column)
        column[0] = AES.galoisMult(temp[0],14) ^ AES.galoisMult(temp[3],9) ^ AES.galoisMult(temp[2],13) ^ AES.galoisMult(temp[1],11)
        column[1] = AES.galoisMult(temp[1],14) ^ AES.galoisMult(temp[0],9) ^ AES.galoisMult(temp[3],13) ^ AES.galoisMult(temp[2],11)
        column[2] = AES.galoisMult(temp[2],14) ^ AES.galoisMult(temp[1],9) ^ AES.galoisMult(temp[0],13) ^ AES.galoisMult(temp[3],11)
        column[3] = AES.galoisMult(temp[3],14) ^ AES.galoisMult(temp[2],9) ^ AES.galoisMult(temp[1],13) ^ AES.galoisMult(temp[0],11)

    # apply mixColumn on all columns
    @staticmethod
    def mixColumns(state):
        for i in range(4):
            column = []
            # take out the i-th column
            for j in range(4):
                column.append(state[j*4+i])
            # apply mixColumn
            AES.mixColumn(column)
            # write the new values back into the state table
            for j in range(4):
                state[j*4+i] = column[j]

    # inverse of mixColumns
    @staticmethod
    def mixColumnsInv(state):
        for i in range(4):
            column = []
            # take out the i-th column
            for j in range(4):
                column.append(state[j*4+i])
            # apply mixColumn
            AES.mixColumnInv(column)
            # write new values back into the state table
            for j in range(4):
                state[j*4+i] = column[j]

    # takes 4-byte word and iteration number
    @staticmethod
    def keyScheduleCore(word, i):
        # rotate word 1 byte to the left
        word = AES.rotate(word, 1)
        newWord = []
        # apply sbox substitution on all bytes of word
        for byte in word:
            newWord.append(AES.sbox[byte])
        # XOR rcon[i] with the first byte of the word
        newWord[0] = newWord[0] ^ AES.rcon[i]
        return newWord

    # expand 256 bit(32 bytes) cipher key into 240 byte key from which
    # each round key is derived
    @staticmethod
    def expandKey(cipherKey):
        cipherKeySize = len(cipherKey)
        assert cipherKeySize == 32
        # container for expanded key
        expandedKey = []
        currentSize = 0
        rconIter = 1
        # copy the first 32 bytes of the cipher key to the expanded key
        expandedKey += cipherKey
        currentSize += cipherKeySize
        # generate the remaining bytes until we get a total key size
        # of 240 bytes
        while currentSize < 240:
            # assign previous 4 bytes to the temporary storage t
            t = expandedKey[currentSize-4:currentSize]
            # every 32 bytes apply the core schedule to t
            if currentSize % cipherKeySize == 0:
                t = AES.keyScheduleCore(t, rconIter)
                rconIter += 1
            # since we're using a 256-bit key, add an extra sbox transform
            if currentSize % cipherKeySize == 16:
                for i in range(4):
                    t[i] = AES.sbox[t[i]]
            # The next 4 bytes in the expanded key is t XOR with the 4-byte block 
            # [16,24,32] bytes before the end of the current expanded key
            for i in range(4):
                expandedKey.append(((expandedKey[currentSize - cipherKeySize]) ^ (t[i])))
                currentSize += 1
        return expandedKey

    # returns a 16-byte round key based on an expanded key and round number
    @staticmethod
    def createRoundKey(expandedKey, n):
        return expandedKey[n*16:n*16+16]

    ## One AES round

    # aesRound applies each of the four transformations in order
    @staticmethod
    def aesRound(state, roundKey):
        AES.subBytes(state)
        AES.shiftRows(state)
        AES.mixColumns(state)
        AES.addRoundKey(state, roundKey)

    # aesRoundInv applies each of the four inverse transformations
    @staticmethod
    def aesRoundInv(state, roundKey):
        AES.addRoundKey(state, roundKey)
        AES.mixColumnsInv(state)
        AES.shiftRowsInv(state)
        AES.subBytesInv(state)

    ## AES main functions

    # wrapper function for 14 rounds of AES since we're using a 256-bit key
    @staticmethod
    def aesMain(state, expandedKey, numRounds=14):
        roundKey = AES.createRoundKey(expandedKey, 0)
        AES.addRoundKey(state, roundKey)
        for i in xrange(1, numRounds):
            roundKey = AES.createRoundKey(expandedKey, i)
            AES.aesRound(state, roundKey)
        # final round - leave out the mixColumns transformation
        roundKey = AES.createRoundKey(expandedKey, numRounds)
        AES.subBytes(state)
        AES.shiftRows(state)
        AES.addRoundKey(state, roundKey)

    # 14 rounds of AES inverse rounds since we're using a 256-bit key
    @staticmethod
    def aesMainInv(state, expandedKey, numRounds=14):
        # create roundKey for last round since we're going in reverse
        roundKey = AES.createRoundKey(expandedKey, numRounds)
        # addRoundKey is its own inverse
        AES.addRoundKey(state, roundKey)
        AES.shiftRowsInv(state)
        AES.subBytesInv(state)
        for i in reversed(xrange(1, numRounds)):
            roundKey = AES.createRoundKey(expandedKey, i)
            AES.aesRoundInv(state, roundKey)
        # roundKey for first round
        roundKey = AES.createRoundKey(expandedKey, 0)
        AES.addRoundKey(state, roundKey)

    # encrypt a single block of plaintext
    @staticmethod
    def aesEncrypt(plaintext, key):
        block = copy(plaintext)
        expandedKey = AES.expandKey(key)
        AES.aesMain(block, expandedKey)
        return block

    # decrypt a single block of ciphertext
    @staticmethod
    def aesDecrypt(ciphertext, key):
        block = copy(ciphertext)
        expandedKey = AES.expandKey(key)
        AES.aesMainInv(block, expandedKey)
        return block

    ## Some handy utility functions

    # create a key from a user-supplied password using SHA-256
    @staticmethod
    def passwordToKey(password):
        sha256 = hashlib.sha256()
        sha256.update(password)
        key = map(ord, sha256.digest())
        return key

    # append PKCS7 padding
    # if len(bytes) is multiple of block size, will add a new block
    @staticmethod
    def appendPadding(bytes):
        numpads = 16 - (len(bytes) % 16)
        # bytes += [numpads] * numpads
        return bytes + [numpads] * numpads

    # strip PKCS7 padding
    @staticmethod
    def stripPadding(bytes):
        if len(bytes) % 16 or not bytes:
            raise ValueError("Input of len %d can't be PCKS7-padded" % len(bytes))
        numpads = bytes[-1]
        if numpads > 16:
            raise ValueError("String ending with %r can't be PCKS7-padded" % bytes[-1])
        # del bytes[-numpads:]
        return bytes[:-numpads]

    # convert state table to AES test vector format hex string
    @staticmethod
    def stateToHexString(state):
        return ''.join(map(lambda x:"{:02x}".format(x), state))

    # convert AES test vector format hex string to byte array
    @staticmethod
    def hexStringToState(text):
        return map(lambda x:int(x,16), [text[i:i+2] for i in range(0, len(text), 2)])
    
    # tranpose state table
    @staticmethod
    def transpose(data):
        state = []
        for r in xrange(4):
            for c in xrange(4):
                state.append(data[c*4+r])
        return state

    # constructor
    def __init__(self, key):
        self.key = key

    # encrypt using self.key
    # supports three modes of operations
    def encrypt(self, plaintext, mode, iv=None):
        # add PKCS7 padding
        plaintext = AES.appendPadding(plaintext)
        # calculate number of blocks
        num_blocks = len(plaintext) / 16
        # ECB Mode
        if mode == "ECB":
            ciphertext = []
            for i in xrange(num_blocks):
                block = plaintext[i*16:i*16+16]
                encrypted_block = AES.aesEncrypt(block, self.key)
                ciphertext += encrypted_block
        # CBC Mode
        elif mode == "CBC":
            # if IV is not given, use random IV
            if iv == None:
                iv = map(ord, os.urandom(16))
            # write encrypted IV
            ciphertext = AES.aesEncrypt(iv, self.key)
            for i in xrange(num_blocks):
                block = plaintext[i*16:i*16+16]
                if i == 0:
                    for i in xrange(16):
                        block[i] ^= iv[i]
                else:
                    for i in xrange(16):
                        block[i] ^= encrypted_block[i]
                encrypted_block = AES.aesEncrypt(block, self.key)
                ciphertext += encrypted_block
        # OFB Mode
        elif mode == "OFB":
            # if IV is not given, use random IV
            if iv == None:
                iv = map(ord, os.urandom(16))
            # write IV
            ciphertext = iv
            for i in xrange(num_blocks):
                if i == 0:
                    pad = AES.aesEncrypt(iv, self.key)
                else:
                    pad = AES.aesEncrypt(pad, self.key)
                block = plaintext[i*16:i*16+16]
                encrypted_block = map(lambda x,y: x^y, block, pad)
                ciphertext += encrypted_block
        return ciphertext

    # decrypt using self.key
    def decrypt(self, ciphertext, mode):
        # calculate number of blocks
        num_blocks = len(ciphertext) / 16
        plaintext = []
        # ECB Mode
        if mode == "ECB":
            for i in xrange(num_blocks):
                block = ciphertext[i*16:i*16+16]
                decrypted_block = AES.aesDecrypt(block, self.key)
                plaintext += decrypted_block
        # CBC Mode
        elif mode == "CBC":
            # read and decrypt IV
            iv = AES.aesDecrypt(ciphertext[:16], self.key)
            prev_block = iv
            for i in xrange(1, num_blocks):
                block = ciphertext[i*16:i*16+16]
                decrypted_block = AES.aesDecrypt(block, self.key)
                for i in xrange(16):
                    decrypted_block[i] ^= prev_block[i]
                plaintext += decrypted_block
                prev_block = block
        # OFB Mode
        elif mode == "OFB":
            # read IV
            iv = ciphertext[:16]
            for i in xrange(1, num_blocks):
                if i == 1:
                    pad = AES.aesEncrypt(iv, self.key)
                else:
                    pad = AES.aesEncrypt(pad, self.key)
                block = ciphertext[i*16:i*16+16]
                decrypted_block = map(lambda x,y: x^y, block, pad)   
                plaintext += decrypted_block
        # strip PKCS7 padding
        plaintext = AES.stripPadding(plaintext)
        return plaintext

    # encrypt file using self.Key
    # default mode is CBC
    def encryptFile(self, inputfile, outputfile=None, mode="CBC", iv=None):
        with open(inputfile, 'rb') as infile:
            plaintext = map(ord, infile.read())
            ciphertext = self.encrypt(plaintext, mode, iv)
            # if user did not specify output filename
            # use input filename plus .aes extension
            if not outputfile:
                outputfile = inputfile + ".aes"
                print "Using", outputfile, "for output file name"
            with open(outputfile, 'wb') as outfile:
                outfile.write(''.join(map(chr, ciphertext)))

    # decrypt file using self.key
    # default mode is CBC
    def decryptFile(self, inputfile, outputfile=None, mode="CBC"):
        with open(inputfile, 'rb') as infile:
            ciphertext = map(ord, infile.read())
            plaintext = self.decrypt(ciphertext, mode)
            # if user did not supply output file name
            # use decrypted_ + inputfilename
            if not outputfile:
                outputfile = "decrypted_" + inputfile
                if outputfile[-4:] == ".aes":
                    outputfile = outputfile[:-4]
                print "Using", outputfile, "for output file name"
            with open(outputfile, 'wb') as outfile:
                outfile.write(''.join(map(chr, plaintext)))


## Command line interface

# print usage
def printUsage():
    print "python aes.py [-e <input file> | -d <input file>] [(optional) -o <output file>]"
    print "You will be prompted for a password after you specify the encryption/decryption args."
    sys.exit(2)

# gather command line arguments and validate input
def main(argv):
    # containers for command line arguments
    encrypt = False
    decrypt = False
    inputfile = None
    outputfile = None
    # if not arguments passed
    if not argv:
        printUsage()
    # parse command line arguments
    try:
        opts, args = getopt.getopt(argv,"he:d:o:")
    except getopt.GetoptError:
        printUsage()
    for opt, arg in opts:
        if opt == '-h':
            printUsage()
        elif opt in ("-e"):
            inputfile = arg
            encrypt = True
        elif opt in ("-d"):
            inputfile = arg
            decrypt = True
        elif opt in ("-o"):
            outputfile = arg
    # if -e and -d are passed at the same time
    if decrypt == encrypt:
        print "Please choose one between encrypt and decrpyt."
        printUsage()
    # get password and key
    password = getpass.getpass("Password: ")
    key = AES.passwordToKey(password)
    # create aes instance
    aes = AES(key)
    # encrypt file per user instructions
    if encrypt:
        print "Encrypting", inputfile, "..."
        aes.encryptFile(inputfile, outputfile=outputfile)
        print "Encryption complete."
    # decrypt file per user instructions
    elif decrypt:
        print "Decrypting", inputfile, "..."
        aes.decryptFile(inputfile, outputfile=outputfile)
        print "Decryption complete."

if __name__ == "__main__":
    main(sys.argv[1:])