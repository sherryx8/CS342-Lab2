import sys
from set1challenge3 import singleByteXORDecode
from set1challenge3 import scorePlaintext


###############
# CHALLENGE 4 #
###############

def detectSingleCharXOR(dataFilePath):
    encryptedFile = open(dataFilePath, "r")
    maxScore = 0
    maxPlaintext = ""
    maxLine = ""
    for encryptedLine in encryptedFile.readlines():
        encryptedLine = encryptedLine.strip()
        decodedLine = singleByteXORDecode(encryptedLine)
        decodedScore = scorePlaintext(decodedLine[0])
        if( decodedScore > maxScore):
            maxScore = decodedScore
            maxPlaintext = decodedLine
            maxLine = encryptedLine
    encryptedFile.close()
    return (maxPlaintext[0], maxLine)

def main():
    if len(sys.argv) > 1:
        result = detectSingleCharXOR(sys.argv[1])
    else:
        result = detectSingleCharXOR("set1challenge4data.txt")
    print("The message encrypted with single character xor is: ")
    print(result[1])
    print("\nThe decrypted text of this message is:")
    print(result[0])


if __name__ == '__main__':
    main()
