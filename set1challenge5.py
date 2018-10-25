import sys
import binascii

###############
# CHALLENGE 5 #
###############

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

def main():
    if len(sys.argv) > 2:
        print("The encoded message is: ")
        print(repeatingXOR(sys.argv[1], sys.argv[2]))
    else:
        stanza = "Burning 'em, if you ain't quick and nimble \nI go crazy when I hear a cymbal"
        key = "ICE"
        print("The encoded message,", stanza, ", with key", key, "is : ")
        print(repeatingXOR(stanza, key))

if __name__ == '__main__':
    main()
