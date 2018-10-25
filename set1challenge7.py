import sys
import os
import base64
import codecs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

###############
# CHALLENGE 7 #
###############

def decryptAESECB(key,ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext)


def decryptAESECBfromFile(filePath, key):
    encryptedFile = open(filePath, 'r')
    ciphertext = encryptedFile.read()
    encryptedFile.close()
    return codecs.decode(decryptAESECB( key = bytes(key, 'ascii'), ciphertext = bytes(base64.b64decode(ciphertext))), 'ascii')


def main():
    if len(sys.argv) > 2:
        key = sys.argv[2]
        result = decryptAESECBfromFile(sys.argv[1], key)
    else:
        key = b"YELLOW SUBMARINE"
        result = decryptAESECBfromFile("set1challenge7data.txt", "YELLOW SUBMARINE")
    print("The decoded message is using key,", key, ", is : \n")
    print(result)

if __name__ == '__main__':
    main()
