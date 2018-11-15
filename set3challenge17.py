import sys
import random

from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESCBC
from set2challenge10 import decryptAESCBC
from set2challenge11 import generateRandomKey
from set2challenge15 import validatePKCS7Padding

################
# CHALLENGE 17 #
################

randomStrings = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                 b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                 b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                 b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                 b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                 b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                 b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                 b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                 b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                 b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

randkey17 = None
randIV17 = None
def encryptRandomString(randomStrings):
    global randkey17
    global randIV17
    randomString = randomStrings[random.randint(0, len(randomStrings)-1)]
    if randkey17 is None:
        randkey17 = generateRandomKey(16)
    if randIV17 is None:
        randIV17 = generateRandomKey(16)
    ciphertext = encryptAESCBC(randkey17, randomString, randIV17)
    return randIV17 + ciphertext

def paddingOracle(ciphertext):
    plaintext = decryptAESCBC(randkey17, ciphertext, randIV17)
    return (True if validatePKCS7Padding(plaintext) else False, plaintext)

def decryptCBCWithPaddingOracle(ciphertext):
    plaintext = []
    intermediary = []
    ctarray = bytearray(ciphertext)
    offset = 1
    #loop through each byte of ciphertext starting from the back
    for b in range(len(ciphertext)-16-1, -1, -1):
        if (offset > 16):
            ctarray = bytearray(ciphertext[:b+18])
            offset = 1
            intermediary = []
        #to prevent false positives in padding
        ctarray[b-1] = ctarray[b-1]^1
        #attempt each character
        for c in range(256):
            ctarray[b] = c
            res = paddingOracle(bytes(ctarray))
            if res[0]:
                i2 = c^offset
                intermediary = [i2] + intermediary
                plaintext = [(ciphertext[b]^i2)] + plaintext
                offset += 1
                for x in range(offset-1):
                    ctarray[b+x] = intermediary[x]^offset
                break;

    return bytes(plaintext)

def testall():
    global randomStrings
    res = []
    for s in randomStrings:
        print("------------")
        print("expected string:    ", s)
        ciphertext = encryptRandomString([s])
        plaintext = validatePKCS7Padding(decryptCBCWithPaddingOracle(ciphertext))
        print("decrypted string:   ", plaintext)
        res.append((s, plaintext))
    return res

def main():
    testall()

if __name__ == '__main__':
    main()
