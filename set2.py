import codecs
import binascii

###############
# CHALLENGE 9 #
###############

def pkcs7Padding(text, blocksize):
    textbytes= bytearray(text)
    padding =  ( blocksize - (len(textbytes) % blocksize)) if ((len(textbytes) % blocksize) is not 0) else 0
    #print(padding)
    for i in range(padding):
        textbytes.append(padding)
    return bytes(textbytes)

txt = b"YELLOW SUBMARINEKKKKYELLOW SUBMARINEKKKKd"
blocksize = 20
print(pkcs7Padding(txt, blocksize))

###############
# CHALLENGE 10 #
###############

from set1challenge3 import XORbySingleChar
#from set1challenge5 import repeatingXOR
from set1challenge7 import decryptAESECB
from set1challenge1 import hexTo64
from set1challenge2 import fixedXOR
import sys
import os
import base64
import codecs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
def repeatingXOR(string, key):
    i = 0
    encryptedString = bytearray("", 'ascii')
    for s in string:
        keyi = i % len(key)
        char = key[keyi]
        i += 1
        encryptedString.append(s ^ char)
    return bytes(encryptedString)

def encryptAESECB(key,plaintext):
    encrypter = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
    return encrypter.update(plaintext)

def encryptAESCBCreal(key,plaintext):
    encrypter = Cipher(algorithms.AES(key), modes.CBC(b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"), backend=default_backend()).encryptor()
    return encrypter.update(plaintext)

def encryptAESCBC(key, plaintext, iv):
    paddedtext = pkcs7Padding(plaintext, 16)
    print(len(paddedtext))
    print(len(plaintext))
    plainblocks = [paddedtext[i*16:(i+1)*16] for i in range(int(len(paddedtext)/16))]
    print(len(plainblocks)*16)
    encryptedBlocks = []
    prev = iv
    for block in plainblocks:
        #prev = (encryptAESECB(key, repeatingXOR(bytes(block, 'ascii'), prev)))
        prev = (encryptAESECB(key, repeatingXOR(block, prev)))
        encryptedBlocks.append(prev)
    #print(encryptedBlocks)

    return b''.join(encryptedBlocks)

def decryptAESCBC(key, ciphertext, iv):
    #split into blocks
    cipherblocks = [ciphertext[i*16:(i+1)*16] for i in range(int(len(ciphertext)/16))]
    decryptedBlocks = []

    prev = iv
    for block in cipherblocks:
        #print(block)
        plainblock = repeatingXOR(decryptAESECB(key, block), prev)
        prev = block
        decryptedBlocks.append(plainblock)
    return b''.join(decryptedBlocks)

def encryptAESCBCfromFile(filePath, key):
    encryptedFile = open(filePath, 'r')
    plaintext = encryptedFile.read()
    encryptedFile.close()
    expectedCiphertext = encryptAESCBCreal(key = key, plaintext = pkcs7Padding(bytes(plaintext, 'ascii'), 16))
    print("excpected", expectedCiphertext)
    print(len(expectedCiphertext))
    return encryptAESCBC( key = key, plaintext = bytes(plaintext, 'ascii'), iv = b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")

print("actual:  ", encryptAESCBCfromFile("set2challenge10data.txt", b"YELLOW SUBMARINE"))
print(decryptAESCBC(b"YELLOW SUBMARINE", encryptAESCBCfromFile("set2challenge10data.txt", b"YELLOW SUBMARINE"), b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))

################
# CHALLENGE 11 #
################

import random
import os

from set1challenge8 import checkLineforECB

def generateRandomKey(bytesize):
    return os.urandom(bytesize)

def encryptionOracle(plaintext):
    CBCmode = (random.randint(0, 1) == 0)
    bytesBefore = (random.randint(5, 10))
    bytesAfter = (random.randint(5, 10))
    plaintext = bytes(bytesBefore) + plaintext + bytes(bytesAfter)
    #print(CBCmode)
    #print(bytesBefore)
    #print(bytesAfter)
    key = generateRandomKey(16)
    #print(key)
    if(CBCmode):
        iv = bytes(generateRandomKey(16))
        ciphertext = encryptAESCBC(key, plaintext, iv)
        print("using CBC mode")
    else:
        print("using ECB mode")
        ciphertext = encryptAESECB(key, plaintext)
    return ciphertext

def detectECBorCBC():
    plaintext = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    ciphertext = encryptionOracle(plaintext)
    return "detected ECB mode" if checkLineforECB(ciphertext) else "detected CBC mode"

print(encryptionOracle(b"xxxxxxxxxxnjnjklhjjvjhvjkvxxx\xf8xxxxxxx"))
print(detectECBorCBC())


################
# CHALLENGE 12 #
################

randkey = None
unknownstring = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
def encryptionECBOracle(plaintext, unknownstring):
    global randkey
    #bytesBefore = (random.randint(5, 10))
    #bytesAfter = (random.randint(5, 10))
    if randkey is None:
        randkey = bytes(generateRandomKey(16))
    plaintext = pkcs7Padding(plaintext + unknownstring, 16)
    ciphertext = encryptAESECB(randkey, plaintext)

    return ciphertext


# Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on.
#Discover the block size of the cipher. You know it, but do this step anyway.

# Detect that the function is using ECB. You already know, but do this step anyways.

# Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes,
#make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.

# Make a dictionary of every possible last byte by feeding different strings to the oracle;
#for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

# Match the output of the one-byte-short input to one of the entries in your dictionary.
#You've now discovered the first byte of unknown-string.

# Repeat for the next byte.

def byteAtATimeDecryptAESECB(unknown):
    ciphertext = encryptionECBOracle(b"", unknown)
    print(len(unknown))
    print(len(ciphertext))
    if (checkLineforECB(encryptionECBOracle(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", unknown))):
        keysize = findKeySize(ciphertext)
        print(keysize)
        #for byte in ciphertext:

        plaintext = ""
        for i in range(len(ciphertext)):
            pad = len(plaintext) % keysize
            shortbyte = ("x"*(15-pad)) + plaintext
            # print(shortbyte)
            shortdict = createShortDict(shortbyte, unknown, keysize)
            shortbyte2 = ("x"*(15-pad))
            # print(shortbyte)
            byteresult = encryptionECBOracle(bytes(shortbyte2, 'utf-8'), unknown)
            # print(byteresult[:16])
            # print(shortbyte, byteresult[:len(shortbyte)+1])
            bytechar = shortdict[byteresult[:len(shortbyte)+1]]
            # print(ord(bytechar))
            if ord(bytechar) is 1:
                break;
            plaintext += bytechar
            #print(plaintext)

        # print(base64.b64decode(plaintext))
        print(plaintext)
        print("using ECB")

def createShortDict(shortbyte, unknown, keysize):
    byteshort_dict = {}
    for i in range(256):
        byteshort_in = bytes(shortbyte + chr(i), 'utf-8')
        byteshort_out = encryptionECBOracle(byteshort_in, unknown)
        byteshort_dict[byteshort_out[:len(byteshort_in)]] = chr(i)
    return byteshort_dict


def findKeySize(unknown):
    for i in range(2, 80):
        plaintext = bytes("x"*i*2, 'ascii')
        ciphertext = encryptionECBOracle(plaintext, unknown)
        #print(i)
        #print(ciphertext[0:i])
        #print(ciphertext[i:i*2])

        if (i*2 < len(ciphertext)) and (ciphertext[0:i] == ciphertext[i:i*2]):

            return i
            break;


encryptionECBOracle(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", unknownstring)
byteAtATimeDecryptAESECB(unknownstring)

base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

################
# CHALLENGE 13 #
################

cookie = "foo=bar&baz=qux&zap=zazzle"

def cookieParse(cookie):
    cookieDict = {}
    cookieElements = cookie.split('&')
    for element in cookieElements:
        keyval = element.split('=')
        cookieDict[keyval[0]] = keyval[1]
    return cookieDict

def cookieMake(cookieDict):
    cookie = []
    for key in cookieDict:
        cookie.append(str(key + "=" + str(cookieDict[key])))
    return '&'.join(cookie)

print(cookieParse(cookie))
print(cookieMake(cookieParse(cookie)))

def profileFor(email):
    email = email.replace("=", "").replace("&", "")
    userDict = {}
    userDict["email"] = email
    userDict["uid"] = 12
    userDict["role"] = "user"
    return cookieMake(userDict)

profileFor("foo@bar.com")

randkey13 = bytes(generateRandomKey(16))
plaintext13 = pkcs7Padding(bytes(profileFor("xxxxxxxxxxxxx"), 'utf-8'), 16)
print(plaintext13)
ciphertext13 = encryptAESECB(randkey13,plaintext13)

#make last chunk role=user
#figure out how to encode "admin"
#replace with role=admin
decryptAESECB(randkey13, ciphertext13)

def cutAndPasteECB():
    evilEmail = "xxxx@xxxx.com"
    e1 = bytearray(encryptAESECB(randkey13, pkcs7Padding(bytes(profileFor(evilEmail), 'utf-8'), 16)))
    evilAdmin = "xxxxxxxxxxadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    #evilAdmin = "xxxxxxxxxxadmin\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a"
    e2 = bytearray(encryptAESECB(randkey13, pkcs7Padding(bytes(profileFor(evilAdmin), 'utf-8'), 16)))
    encryptedAdmin = e2[16:16*2]
    print(encryptedAdmin[1])
    #replace last chunk with admin
    for i in range(16):
        #print(encryptedAdmin[i])
        e1[(-(16-i))] = encryptedAdmin[i]
    e3 = bytes(e1)
    d = decryptAESECB(randkey13, e3)
    return validatePKCS7Padding(d, padlen = 16)#d, e3

print(cookieParse(codecs.decode(cutAndPasteECB(), 'ascii')))

################
# CHALLENGE 14 #
################


import random
randkey14 = None
randPrefixlen = None #needs to be larger than blocksize
randPrefix = None
unknownstring = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
#unknownstring = b"xxxxxxxxxxxxxxxxx"

def encryptionECBOracleUnknownPrepend(plaintext, unknownstring):
    global randkey14
    global randPrefixlen
    #bytesBefore = (random.randint(5, 10))
    #bytesAfter = (random.randint(5, 10))
    if randkey14 is None:
        randkey14 = bytes(generateRandomKey(16))
    if randPrefixlen is None:
        randPrefixlen = random.randint(0, 128)
    randPrefix = bytes(generateRandomKey(randPrefixlen))

    plaintext = pkcs7Padding(randPrefix + plaintext + unknownstring, 16)
    ciphertext = encryptAESECB(randkey14, plaintext)

    return ciphertext

ciphertext14 = encryptionECBOracleUnknownPrepend(b"aaaaa", unknownstring)
decryptAESECB(bytes(randkey14), ciphertext14)

def byteAtATimeDecryptAESECBUnknownPrepend(unknown):
    ciphertext = encryptionECBOracleUnknownPrepend(b"", unknownstring)

    keysize = findKeySize(ciphertext)
    print(keysize)

    prependlen = findPrependSize(keysize)
    print(prependlen)

    plaintext = ""
    for i in range(len(ciphertext)):
        pad = (len(plaintext)+prependlen[1]+prependlen[0]) % keysize #14 +2 - #128
        shortbyte = ("x"*(keysize-pad -1+prependlen[0])) + plaintext
        #print(shortbyte)
        #print(len(shortbyte))
        shortdict = createShortDictUnknownPrepend(shortbyte, unknown, keysize, prependlen)
        shortbyte2 = ("x"*(keysize-pad -1+prependlen[0]))
        #print(shortdict)
        byteresult = encryptionECBOracleUnknownPrepend(bytes(shortbyte2, 'utf-8'), unknown)

        # print(shortbyte, byteresult[:len(shortbyte)+1])
        searchlen = len(shortbyte)+1+prependlen[1]
        #print(searchlen)
        #print(byteresult[:searchlen])
        bytechar = shortdict[byteresult[prependlen[1]+prependlen[0]:searchlen]]
        #print(ord(bytechar))
        if ord(bytechar) is 1:
            break;
        plaintext += bytechar
        #print(plaintext)

    # print(base64.b64decode(plaintext))
    print(plaintext)
    print("using ECB")

    return base64.b64decode(plaintext)

print(byteAtATimeDecryptAESECBUnknownPrepend(unknownstring))

def createShortDictUnknownPrepend(shortbyte, unknown, keysize, prependlen):
    byteshort_dict = {}
    for i in range(256):
        byteshort_in = bytes(shortbyte + chr(i), 'utf-8')
        byteshort_out = encryptionECBOracleUnknownPrepend(byteshort_in, unknown)
        byteshort_key = byteshort_out[prependlen[1]+prependlen[0]:len(byteshort_in)+prependlen[1]]
        #print(i, byteshort_key)
        byteshort_dict[byteshort_key] = chr(i)
    return byteshort_dict

def findPrependSize(keysize):
    #not allowed to use this function, need to use oracle
    base = encryptAESECB(randkey14, b"xxxxxxxxxxxxxxxx")
    xblock = ""
    #find which k gives you two identical blocks
    for k in range(keysize):
        guess = encryptionECBOracleUnknownPrepend(bytes("x"*(k + keysize*2), 'utf-8'), unknownstring)
        #look for two consequtive blocks
        for i in range(1, int(len(guess)/keysize)):
            xblock1 = guess[(i-1)*keysize: (i)*keysize]
            xblock2 = guess[(i)*keysize: (i+1)*keysize]
            if xblock1 == xblock2:
                print("equal blocks found for offset", k)
                xblock = xblock1
                #confirm xblock is correct using a's
                guess2 = encryptionECBOracleUnknownPrepend(bytes("a"*(k + keysize*2), 'utf-8'), unknownstring)

                ablock1 = guess2[(i-1)*keysize: (i)*keysize]
                ablock2 = guess2[(i)*keysize: (i+1)*keysize]
                if ablock1 == ablock2 and ablock1 != xblock1:
                    xblock = xblock1
                    return k, (i-2)*keysize+(keysize-k)
    return False

findPrependSize(16)
print(len(randPrefix))
print(randPrefix)

byteAtATimeDecryptAESECBUnknownPrepend( unknownstring)

################
# CHALLENGE 15 #
################

def validatePKCS7Padding(paddedBytes, padlen = 16):
    paddedAmount = paddedBytes[-1]
    unpaddedBytes = bytearray(paddedBytes)
    if len(paddedBytes) % padlen is not 0:
        return False
    elif paddedAmount <= padlen:
        for i in range(paddedAmount):
            if unpaddedBytes[-1] is not paddedAmount:
                return False
            else:
                unpaddedBytes = unpaddedBytes[:-1]
    return bytes(unpaddedBytes)

print(validatePKCS7Padding(b"ICE ICE BABY\x04\x04\x04\x04"))
print(validatePKCS7Padding(b"ICE ICE BABY IE\x01", 16))
print(validatePKCS7Padding(b"ICE ICE BABY\x05\x05\x05\x05", 16)) #invalid
print(validatePKCS7Padding(b"ICE ICE BABY\x01\x02\x03\x04", 16)) #invalid
print(validatePKCS7Padding(b"ICE\x01", 16)) #invalid

################
# CHALLENGE 16 #
################

#function 1 = encryption
#function 2 = decryption + guard
#function 3 = attacker

################
# CHALLENGE 17 #
################

#flip bits until padding correct
#thats how you know the bit



#confused
