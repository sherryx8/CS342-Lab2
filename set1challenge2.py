
import sys
import codecs
import binascii

###############
# CHALLENGE 2 #
###############



def fixedXOR(buf1, buf2):
    return codecs.encode(hex(int(buf1, 16) ^ int(buf2, 16)), 'ascii')[2:]

def main():
    if len(sys.argv) > 2:
        print("The fixed xor is: ")
        print(fixedXOR(sys.argv[1], sys.argv[2]))
    else:
        b1 = b'1c0111001f010100061a024b53535009181c'
        b2 = b'686974207468652062756c6c277320657965'
        print("The fixed xor of", b1, b2, "is: ")
        print(fixedXOR(b1, b2))

if __name__ == '__main__':
    main()
