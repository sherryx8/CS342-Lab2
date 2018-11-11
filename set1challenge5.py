import sys
import binascii
import codecs

###############
# CHALLENGE 5 #
###############

def repeatingXOR(string, key):
    i = 0
    encryptedString = bytearray("", 'ascii')
    for s in string:
        keyi = i % len(key)
        char = key[keyi]
        i += 1
        encryptedString.append(s ^ char)
    return codecs.encode(bytes(encryptedString), 'hex')

def main():
    if len(sys.argv) > 2:
        print("The encoded message is: ")
        print(repeatingXOR(bytes(sys.argv[1], 'ascii'), bytes(sys.argv[2], 'ascii')))
    else:
        stanza = "Burning 'em, if you ain't quick and nimble \nI go crazy when I hear a cymbal"
        key = "ICE"
        print("The encoded message,", stanza, ", with key", key, "is : ")
        print(repeatingXOR(bytes(stanza, 'ascii'), bytes(key, 'ascii')))


if __name__ == '__main__':
    main()
