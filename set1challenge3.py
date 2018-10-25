import binascii
import codecs
import sys

###############
# CHALLENGE 3 #
###############

def XORbySingleChar(string, char):
    return ''.join(chr(b ^ char) for b in string)

def singleByteXORDecode(encoded):
    intencoded = binascii.unhexlify(encoded)
    decodedstrings = [(XORbySingleChar(intencoded, i), chr(i)) for i in range(256)]
    return max(decodedstrings, key=lambda s: scorePlaintext(s[0]))

def scorePlaintext(string):
    count = 0;
    for c in string:
        count = count + 1 if (c in "eEtTaAoOiInNsShHrRdDlLuU") else count
        count = count + 10 if (c is ' ') else count
    return count

def main():
    if len(sys.argv) > 1:
        print("The decoded message is: ")
        print(singleByteXORDecode(sys.argv[1])[0])
    else:
        encoded = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        print("The decoded message is: ")
        print(singleByteXORDecode(encoded)[0])

if __name__ == '__main__':
    main()


#singleByteXORDecode(encoded)
