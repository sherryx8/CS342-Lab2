import sys
import codecs
from set2challenge9 import pkcs7Padding
from set2challenge10 import encryptAESECB
from set2challenge10 import decryptAESECB
from set2challenge11 import generateRandomKey
from set2challenge15 import validatePKCS7Padding

################
# CHALLENGE 13 #
################

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

def profileFor(email):
    email = email.replace("=", "").replace("&", "")
    userDict = {}
    userDict["email"] = email
    userDict["uid"] = 12
    userDict["role"] = "user"
    return cookieMake(userDict)

def cutAndPasteECB():
    randkey13 = bytes(generateRandomKey(16))
    evilEmail = "xxxx@xxxx.com"
    e1 = bytearray(encryptAESECB(randkey13, pkcs7Padding(bytes(profileFor(evilEmail), 'utf-8'), 16)))
    evilAdmin = "xxxxxxxxxxadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    e2 = bytearray(encryptAESECB(randkey13, pkcs7Padding(bytes(profileFor(evilAdmin), 'utf-8'), 16)))
    encryptedAdmin = e2[16:16*2]
    #replace last chunk with admin
    for i in range(16):
        e1[(-(16-i))] = encryptedAdmin[i]
    d = decryptAESECB(randkey13, bytes(e1))
    return bytes(e1), validatePKCS7Padding(d, padlen = 16)

def main():
    result = cutAndPasteECB()
    print("The evil cookie has been created: ", result[0])
    print("It decrypts into: ", result[1])
    print("It parses into: ", cookieParse(codecs.decode(result[1], 'ascii')))

if __name__ == '__main__':
    main()
