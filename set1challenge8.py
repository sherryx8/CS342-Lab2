import sys

###############
# CHALLENGE 8 #
###############

def findECBciphertext(filePath):
    encryptedFile = open(filePath, "r")
    ciphertext = []
    for line in encryptedFile.readlines():
        line = line.strip()
        if (checkLineforECB(line)):
            ciphertext.append(line)
    return ciphertext

def checkLineforECB(line):
    for i in range(int(len(line)/16)):
        for j in range(i+1, int(len(line)/16)):
            if line[i*16:(i+1)*16] == line[j*16:(j+1)*16]:
                return True
    return False


def main():
    if len(sys.argv) > 1:
        result = findECBciphertext(sys.argv[1])
    else:
        result = findECBciphertext("set1challenge8data.txt")
    print("The ciphertext encrypted with AES in ECB mode is:  ")
    print(result[0])

if __name__ == '__main__':
    main()
