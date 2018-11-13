import random
import sys
import base64
from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESECB
from set2challenge11 import generateRandomKey

################
# CHALLENGE 12 #
################

randkey = None
def encryptionECBOracle(plaintext):
    unknownstring = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

    global randkey
    if randkey is None:
        randkey = bytes(generateRandomKey(16))
    plaintext = pkcs7Padding(plaintext + unknownstring, 16)
    ciphertext = encryptAESECB(randkey, plaintext)
    return ciphertext

def byteAtATimeDecryptAESECB():
    ciphertext = encryptionECBOracle(b"")
    keysize = findKeySize()
    plaintext = ""
    for i in range(len(ciphertext)):
        pad = len(plaintext) % keysize
        shortbyte = ("x"*(keysize-1-pad))
        shortdict = createShortDict(shortbyte + plaintext, keysize)
        byteresult = encryptionECBOracle(bytes(shortbyte, 'utf-8'))
        bytechar = shortdict[byteresult[:len(shortbyte + plaintext)+1]]
        if ord(bytechar) is 1:
            break;
        plaintext += bytechar
    return plaintext

def createShortDict(shortbyte,  keysize):
    byteshort_dict = {}
    for i in range(256):
        byteshort_in = bytes(shortbyte + chr(i), 'utf-8')
        byteshort_out = encryptionECBOracle(byteshort_in)
        byteshort_dict[byteshort_out[:len(byteshort_in)]] = chr(i)
    return byteshort_dict

def findKeySize():
    for i in range(2, 80):
        plaintext = bytes("x"*i*2, 'ascii')
        ciphertext = encryptionECBOracle(plaintext)
        if (i*2 < len(ciphertext)) and (ciphertext[0:i] == ciphertext[i:i*2]):
            return i

def main():
    result = byteAtATimeDecryptAESECB()
    print("The decrypted string is: ", base64.b64decode(result))

if __name__ == '__main__':
    main()
