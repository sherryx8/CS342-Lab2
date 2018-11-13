import sys
import random
import codecs

from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESCBC
from set2challenge10 import decryptAESCBC
from set2challenge11 import generateRandomKey
from set2challenge15 import validatePKCS7Padding

################
# CHALLENGE 16 #
################

#function 1 = encryption
randIV = None
randkey16 = None
def commentEncryption(plaintext):
    global randkey16
    global randIV
    if randkey16 is None:
        randkey16 = generateRandomKey(16)
    if randIV is None:
        randIV = generateRandomKey(16)
    plaintext = plaintext.replace(";", "';'").replace("=", "'='")
    plaintext = "comment1=cooking%20MCs;userdata=" + plaintext + ";comment2=%20like%20a%20pound%20of%20bacon"
    ciphertext = encryptAESCBC(randkey16, pkcs7Padding(bytes(plaintext, 'utf-8'), 16), randIV)
    return ciphertext

#function 2 = decryption + guard
def commentDecryption(ciphertext):
    plaintext =  codecs.decode(validatePKCS7Padding(decryptAESCBC(randkey16, ciphertext, randIV)), 'utf-8', 'ignore')
    admin = (";admin=true;" in plaintext)
    return plaintext, admin

#function 3 = attacker
def generateBitFlippedCiphertext():
    ciphertext = commentEncryption(":admin<true")
    evilciphertext = bytearray(ciphertext)
    evilciphertext[16] = evilciphertext[16] ^ 1
    evilciphertext[22] = evilciphertext[22] ^1
    return bytes(evilciphertext)

def main():
    evilciphertext = generateBitFlippedCiphertext()
    result = commentDecryption(evilciphertext)
    print("The evil ciphertext has been created:", evilciphertext, '\n')
    print("It decrypts into:", bytes(result[0], 'utf-8'), '\n')
    if result[1]:
        print("It contains the substring ';admin=true;'")
    else:
        print("It does not contain the substring ';admin=true;'")

if __name__ == '__main__':
    main()
