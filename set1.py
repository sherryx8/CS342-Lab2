import base64
import codecs

###############
# CHALLENGE 1 #
###############

s = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

def hexTo64(hex):
    #encoded = codecs.encode(codecs.decode(hex, 'hex'), 'base64')
    encoded = base64.b64encode(codecs.decode(hex, 'hex'))
    return encoded


print(hexTo64(s))

###############
# CHALLENGE 2 #
###############

b1 = b'1c0111001f010100061a024b53535009181c'
b2 = b'686974207468652062756c6c277320657965'

def fixedXOR(buf1, buf2):
    return codecs.encode(hex(int(buf1, 16) ^ int(buf2, 16)), 'ascii')

print(fixedXOR(b1, b2))

###############
# CHALLENGE 3 #
###############

encoded = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

import binascii

def XORbySingleChar(string, char):
    return ''.join(chr(b ^ char) for b in string)

def singleByteXORDecode(encoded):
    intencoded = binascii.unhexlify(encoded)
    decodedstrings = [(XORbySingleChar(intencoded, i), chr(i)) for i in range(256)]
    return max(decodedstrings, key=lambda s: scorePlaintext(s[0]))

def scorePlaintext(string):
    etaoinShrdlu = "eEtTaAoOiInNsShHrRdDlLuU"
    count = 0;
    for c in string:
        if c in etaoinShrdlu:
            count += 1
        elif c is ' ':
            count += 10
    return count

singleByteXORDecode(encoded)

###############
# CHALLENGE 4 #
###############

def detectSingleCharXOR(dataFilePath):
    encryptedFile = open(dataFilePath, "r")
    maxScore = 0
    maxPlaintext = ""
    for line in encryptedFile.readlines():
        line = line.strip()
        decodedLine = singleByteXORDecode(line)
        decodedScore = scorePlaintext(decodedLine[0])
        if( decodedScore > maxScore):
            maxScore = decodedScore
            maxPlaintext = decodedLine
    encryptedFile.close()
    return maxPlaintext[0]

print(detectSingleCharXOR("set4data.txt"))

###############
# CHALLENGE 5 #
###############


stanza = "Burning 'em, if you ain't quick and nimble \nI go crazy when I hear a cymbal"

def repeatingXOR(string, key):
    #string = bytes(string, 'ascii')
    #key = bytes(key, 'ascii')
    i = 0
    encryptedString = ""
    for s in string:
        keyi = i % len(key)
        char = key[keyi]
        i += 1
        encryptedString += chr(ord(s) ^ ord(char))
    return binascii.hexlify(bytes(encryptedString, 'ascii'))

print(repeatingXOR(stanza, "ICE"))

###############
# CHALLENGE 6 #
###############

from statistics import mean

def findHammingDist(b1, b2):
    #bytes1 = bytes(b1, 'ascii')
    #bytes2 = bytes(b2, 'ascii')
    #print(binascii.hexlify(b1))
    #print(binascii.hexlify(b2))
    bits1 = str(bin(int(binascii.hexlify(b1), base=16))[2:])
    bits2 = str(bin(int(binascii.hexlify(b2), base=16))[2:])

    maxlen = max(len(bits1), len(bits2))
    bits1 = bits1.zfill(maxlen)
    bits2 = bits2.zfill(maxlen)
    diff = [bin1 != bin2 for bin1, bin2 in zip(bits1, bits2)]
    return sum(diff)
    #
    #
    #
    # #bits1 = bin(int(codecs.encode(b1, 'hex'), base=16))[2:]
    # #bits2 = bin(int(codecs.encode(b2, 'hex'), base=16))[2:]
    # print(bits1)
    # print(bits2)
    # hammingDist = 0
    #
    #
    # if len(bits1) is len(bits2):
    #     for i in range(len(bits1)):
    #         if bits1[i] is not bits2[i]:
    #             hammingDist+=1;
    # else: #strings different lengths
    #     return float('inf')
    # return hammingDist

print(findHammingDist(b"aaaa", b"aabb"))
print(findHammingDist(b"this is a test", b"wokka wokka!!!"))

findHammingDist(b'\x1db', b'\x0bM')

#read in file
def breakRepeatingXOR(encryptedPath):
    encryptedFile = open(encryptedPath, 'rb')
    encryptedData1 = encryptedFile.read()
    #encryptedData1 = ''.join([line.strip() for line in encryptedLines])
    encryptedData1 = codecs.decode(encryptedData1, 'base64')
    #print(type(encryptedData))
    keysizeDists = []
    #keysizeDists = [(ks, findHammingDist(encryptedData1[0:ks], encryptedData1[ks:ks*2])/ks) for ks in range(2, 41)]
    for ks in range(2, 40):
        #if len(encryptedData)%ks is 0:
        dists = []
        dists.append(findHammingDist(encryptedData1[0:ks], encryptedData1[ks:ks*2])/ks)
        dists.append(findHammingDist(encryptedData1[0:ks], encryptedData1[ks*2:ks*3])/ks)
        dists.append(findHammingDist(encryptedData1[0:ks], encryptedData1[ks*3:ks*4])/ks)
        dists.append(findHammingDist(encryptedData1[ks:ks*2], encryptedData1[ks*2:ks*3])/ks)
        dists.append(findHammingDist(encryptedData1[ks:ks*2], encryptedData1[ks*3:ks*4])/ks)
        dists.append(findHammingDist(encryptedData1[ks*2:ks*3], encryptedData1[ks*3:ks*4])/ks)

        dist = mean(dists)

        #dist = findHammingDist(encryptedData1[0:ks], encryptedData1[ks:ks*2])/ks

        #print(encryptedData[0:ks])
        #print(encryptedData[ks:ks*2])
        keysizeDists.append((ks, dist))
    keysizeDists.sort(key=lambda x:x[1])
    print(keysizeDists)

    decodedstrings = []
    for ranking in range(10):
        keysize = keysizeDists[ranking][0]
        predictkey = ""
        for i  in range(keysize):
            keybytes = ""
            for ksblocks in range(int(len(encryptedData1)/keysize)):
                keybytes += chr(encryptedData1[ksblocks*keysize+i])

            #print(len(keybytes))
            res = singleByteXORDecode(binascii.hexlify(codecs.encode(keybytes, 'ascii'))) #but record character for this
            predictkey += res[1]
        #print(keysize, "predictedkey", bytes(predictkey, 'ascii'))
        decodedstrings.append((str(binascii.unhexlify(repeatingXOR(codecs.decode(encryptedData1, 'ascii'), predictkey)), 'ascii'), predictkey))
        print(binascii.unhexlify(repeatingXOR(codecs.decode(encryptedData1, 'ascii'), predictkey)))

    encryptedFile.close()

    return max(decodedstrings, key=lambda s: scorePlaintext(s[0]))

    #find key
    #decrypt like normal



#3836
print(breakRepeatingXOR("set1challenge6data.txt"))


###############
# CHALLENGE 7 #
###############

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def decryptAESECB(key,ciphertext):

    decryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext)


def decryptAESECBfromFile(filePath):
    encryptedFile = open(filePath, 'r')
    ciphertext = encryptedFile.read()
    encryptedFile.close()
    return decryptAESECB( key = b"YELLOW SUBMARINE", ciphertext = bytes(base64.b64decode(ciphertext)))

print(decryptAESECBfromFile("set1challenge7data.txt"))


###############
# CHALLENGE 8 #
###############

def findECBciphertext(filePath):
    encryptedFile = open(filePath, "r")
    ciphertext = []
    for line in encryptedFile.readlines():
        line = line.strip()
        if (checkLineforECB(line)):
            ciphertext.append(line)
    return ciphertext

def checkLineforECB(line):
    for i in range(int(len(line)/16)):
        for j in range(i+1, int(len(line)/16)):
            if line[i*16:(i+1)*16] == line[j*16:(j+1)*16]:
                return True

print(findECBciphertext("set1challenge8data.txt"))

#git remote add origin https:///.......git
#find ciphertext with a 16byte chunk repeat
