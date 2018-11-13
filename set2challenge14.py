import sys
import random
import base64
from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESECB
from set2challenge10 import decryptAESECB
from set2challenge11 import generateRandomKey

################
# CHALLENGE 14 #
################

randkey14 = None
randPrefixlen = None
randPrefix = None
unknownstring = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def findKeySize14():
    for i in range(2, 80):
        plaintext = bytes("x"*i*3, 'ascii')
        ciphertext = encryptionECBOracleUnknownPrepend(plaintext)
        for j in range(int(len(ciphertext)/i)-1):
            if (i*2 < len(ciphertext)) and (ciphertext[j*i:(j+1)*i] == ciphertext[(j+1)*i:(j+2)*i]):
                return i

def encryptionECBOracleUnknownPrepend(plaintext):
    global unknownstring
    global randkey14
    global randPrefixlen

    if randkey14 is None:
        randkey14 = bytes(generateRandomKey(16))
    if randPrefixlen is None:
        randPrefixlen = random.randint(0, 128)

    randPrefix = bytes(generateRandomKey(randPrefixlen))
    plaintext = pkcs7Padding(randPrefix + plaintext + unknownstring, 16)
    ciphertext = encryptAESECB(randkey14, plaintext)
    return ciphertext

def createShortDictUnknownPrepend(shortbyte,keysize, prependlen):
    byteshort_dict = {}
    for i in range(256):
        byteshort_in = bytes(shortbyte + chr(i), 'utf-8')
        byteshort_out = encryptionECBOracleUnknownPrepend(byteshort_in)
        byteshort_key = byteshort_out[prependlen[1]+prependlen[0]:len(byteshort_in)+prependlen[1]]
        byteshort_dict[byteshort_key] = chr(i)
    return byteshort_dict

def findPrependSize(keysize):
    xblock = ""
    #find which k gives you two identical blocks
    for k in range(keysize):
        guess = encryptionECBOracleUnknownPrepend(bytes("x"*(k + keysize*2), 'utf-8'))
        #look for two consequtive blocks
        for i in range(1, int(len(guess)/keysize)):
            xblock1 = guess[(i-1)*keysize: (i)*keysize]
            xblock2 = guess[(i)*keysize: (i+1)*keysize]
            if xblock1 == xblock2:
                xblock = xblock1
                #confirm xblock is correct using a's
                guess2 = encryptionECBOracleUnknownPrepend(bytes("a"*(k + keysize*2), 'utf-8'))
                ablock1 = guess2[(i-1)*keysize: (i)*keysize]
                ablock2 = guess2[(i)*keysize: (i+1)*keysize]
                if ablock1 == ablock2 and ablock1 != xblock1:
                    xblock = xblock1
                    return k, (i-2)*keysize+(keysize-k)
    return False


def byteAtATimeDecryptAESECBUnknownPrepend():
    ciphertext = encryptionECBOracleUnknownPrepend(b"")
    keysize = findKeySize14()
    prependlen = findPrependSize(keysize)
    plaintext = ""
    for i in range(len(ciphertext)):
        pad = (len(plaintext)+prependlen[1]+prependlen[0]) % keysize #14 +2 - #128
        shortbyte = ("x"*(keysize-pad -1+prependlen[0]))
        shortdict = createShortDictUnknownPrepend(shortbyte + plaintext, keysize, prependlen)
        byteresult = encryptionECBOracleUnknownPrepend(bytes(shortbyte, 'utf-8'))
        searchlen = len(shortbyte)+len(plaintext)+1+prependlen[1]
        bytechar = shortdict[byteresult[prependlen[1]+prependlen[0]:searchlen]]
        if ord(bytechar) is 1:
            break;
        plaintext += bytechar
    return plaintext

def main():
    result = byteAtATimeDecryptAESECBUnknownPrepend()
    print("The decrypted string is: ", base64.b64decode(result))

if __name__ == '__main__':
    main()
