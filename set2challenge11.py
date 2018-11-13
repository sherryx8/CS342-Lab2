import random
import os
import sys
from set1challenge8 import checkLineforECB
from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESCBC
from set2challenge10 import encryptAESECB

################
# CHALLENGE 11 #
################

def generateRandomKey(bytesize):
    return os.urandom(bytesize)

def encryptionOracle(plaintext):
    ECBmode = (random.randint(0, 1) == 0)
    bytesBefore = generateRandomKey(random.randint(5, 10))
    bytesAfter = generateRandomKey(random.randint(5, 10))
    plaintext = bytes(bytesBefore) + plaintext + bytes(bytesAfter)
    key = generateRandomKey(16)
    if(ECBmode):
        ciphertext = encryptAESECB(key, plaintext)
    else:
        iv = bytes(generateRandomKey(16))
        ciphertext = encryptAESCBC(key, plaintext, iv)
    return ciphertext, ECBmode

def detectECBorCBC():
    plaintext = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    ciphertext = encryptionOracle(plaintext)

    using = "using ECB mode" if ciphertext[1] else "using CBC mode"
    print(using)

    detectedECBmode = checkLineforECB(ciphertext[0])
    detected = "detected ECB mode" if detectedECBmode else "detected CBC mode"
    print(detected)

    return (1 if (detectedECBmode == ciphertext[1]) else 0)

def main():
    #does 5 iterations by default
    iterations = 5
    correct = 0
    if len(sys.argv) > 1:
        iterations = int(sys.argv[1])
    for i in range(iterations):
        print("---------------")
        correct += detectECBorCBC()
    print(correct, "/", iterations, "passed")

if __name__ == '__main__':
    main()
