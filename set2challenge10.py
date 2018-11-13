import sys
import os
import base64
from set1challenge7 import decryptAESECB
from set2challenge9 import pkcs7Padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

###############
# CHALLENGE 10 #
###############

defaultIV = b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"

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

def encryptAESCBC(key, plaintext, iv = defaultIV):
    paddedtext = pkcs7Padding(plaintext, 16)
    plainblocks = [paddedtext[i*16:(i+1)*16] for i in range(int(len(paddedtext)/16))]
    encryptedBlocks = []
    prev = iv
    for block in plainblocks:
        prev = (encryptAESECB(key, repeatingXOR(block, prev)))
        encryptedBlocks.append(prev)
    return b''.join(encryptedBlocks)

def decryptAESCBC(key, ciphertext, iv = defaultIV):
    cipherblocks = [ciphertext[i*16:(i+1)*16] for i in range(int(len(ciphertext)/16))]
    decryptedBlocks = []
    prev = iv
    for block in cipherblocks:
        plainblock = repeatingXOR(decryptAESECB(key, block), prev)
        prev = block
        decryptedBlocks.append(plainblock)
    return b''.join(decryptedBlocks)

def encryptAESCBCfromFile(key, filePath,  iv = defaultIV):
    encryptedFile = open(filePath, 'r')
    plaintext = encryptedFile.read()
    encryptedFile.close()
    return encryptAESCBC( key = key, plaintext = bytes(plaintext, 'ascii'), iv = iv)

def decryptAESCBCfromFile(key, filePath,  iv = defaultIV):
    encryptedFile = open(filePath, 'r')
    ciphertext = base64.b64decode(encryptedFile.read())
    encryptedFile.close()
    return decryptAESCBC( key = key, ciphertext = ciphertext, iv = iv)

def main():
    if len(sys.argv) > 3: #decrypt/encrypt filepath, key,
        if sys.argv[1] != "0": #decrypt
            plaintext = decryptAESCBCfromFile(bytes(sys.argv[3], 'utf-8'), sys.argv[2])
            print(sys.argv[2], "decrypted with key", sys.argv[3], "is:\n\n", plaintext)
        else: #encrypt
            ciphertext = base64.b64encode(encryptAESCBCfromFile(bytes(sys.argv[3], 'utf-8'), sys.argv[2]))
            print(sys.argv[2], "encrypted with key", sys.argv[3], "is:\n\n", ciphertext)
    elif len(sys.argv) == 1: #default test
        plaintext = decryptAESCBCfromFile(b"YELLOW SUBMARINE", "set2challenge10data.txt")
        ciphertext = base64.b64encode(encryptAESCBC(b"YELLOW SUBMARINE", plaintext))
        print("set2challenge10data.txt decrypted with key 'YELLOW SUBMARINE' and defaultIV is: \n\n", plaintext)
        print("\nand then encrypted again is: \n\n", ciphertext)
    else: #invalid # of arguments
        print("arguments: <0:encrypt, 1:decrypt> <filepath> <key> <iv> ")

if __name__ == '__main__':
    main()
