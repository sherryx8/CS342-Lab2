import binascii
import codecs
import base64
import sys
from statistics import mean
from set1challenge3 import singleByteXORDecode
from set1challenge5 import repeatingXOR
from set1challenge3 import scorePlaintext

###############
# CHALLENGE 6 #
###############

def findHammingDist(b1, b2):
    bits1 = str(bin(int(binascii.hexlify(b1), base=16))[2:])
    bits2 = str(bin(int(binascii.hexlify(b2), base=16))[2:])

    maxlen = max(len(bits1), len(bits2))
    bits1 = bits1.zfill(maxlen)
    bits2 = bits2.zfill(maxlen)

    diff = [bin1 != bin2 for bin1, bin2 in zip(bits1, bits2)]
    return sum(diff)

def findBestKeysizes(encryptedData):
    keysizeDists = []
    for ks in range(2, 40):
        dists = [findHammingDist(encryptedData[ks*i:ks*(i+1)], encryptedData[ks*j:ks*(j+1)]) for i in range(3) for j in range(i+1, 4) ]
        keysizeDists.append((ks, mean(dists)/ks))
    keysizeDists.sort(key=lambda x:x[1])
    return keysizeDists

def breakRepeatingXOR(encryptedPath):
    encryptedFile = open(encryptedPath, 'rb')
    encryptedData = codecs.decode(encryptedFile.read(), 'base64')

    keysizeDists = findBestKeysizes(encryptedData)

    decodedstrings = []
    for ranking in range(3):
        keysize = keysizeDists[ranking][0]
        predictkey = ""
        for i in range(keysize):
            keybytes = codecs.encode(''.join([chr(encryptedData[ksblocks*keysize+i]) for ksblocks in range(int(len(encryptedData)/keysize))]), 'ascii')
            predictkey += singleByteXORDecode(binascii.hexlify(keybytes))[1]
        decodedstring = repeatingXOR(encryptedData, bytes(predictkey, 'ascii'))
        decodedstrings.append((str(binascii.unhexlify(decodedstring), 'ascii'), predictkey))

    encryptedFile.close()

    return max(decodedstrings, key=lambda s: scorePlaintext(s[0]))

def main():
    if len(sys.argv) > 1:
        result = breakRepeatingXOR(sys.argv[1])
    else:
        result = breakRepeatingXOR("set1challenge6data.txt")
    print("The decoded key is: ")
    print(result[1], '\n')
    print("The decoded message is: ")
    print(result[0])

if __name__ == '__main__':
    main()
