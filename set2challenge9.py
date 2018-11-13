import codecs
import binascii
import sys

###############
# CHALLENGE 9 #
###############

def pkcs7Padding(text, blocksize):
    textbytes= bytearray(text)
    padding =  (blocksize - (len(textbytes) % blocksize))
    for i in range(padding):
        textbytes.append(padding)
    return bytes(textbytes)

def main():
    if len(sys.argv) > 2:
        result = pkcs7Padding(bytes(sys.argv[1], 'utf-8'), int(sys.argv[2]))
        print(sys.argv[1], " padded to", sys.argv[2], "bytes is:")
    else:
        result = pkcs7Padding(b"YELLOW SUBMARINE", 20)
        print("'YELLOW SUBMARINE' padded to 20 bytes is:")
    print(result)

if __name__ == '__main__':
    main()
