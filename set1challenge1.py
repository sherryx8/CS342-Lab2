import base64
import codecs
import sys

###############
# CHALLENGE 1 #
###############

def hexTo64(hex):
    encoded = base64.b64encode(codecs.decode(hex, 'hex'))
    return encoded

def main():
    if len(sys.argv) > 1:
        print("The base64 encoding of", sys.argv[1], "is: ")
        print(hexTo64(sys.argv[1]))
    else:
        s = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        print("The base64 encoding of", s, "is: ")
        print(hexTo64(s))

if __name__ == '__main__':
    main()
