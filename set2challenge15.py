import sys
import codecs

################
# CHALLENGE 15 #
################

def validatePKCS7Padding(paddedBytes, padlen = 16):
    paddedAmount = paddedBytes[-1]
    unpaddedBytes = bytearray(paddedBytes)
    if len(paddedBytes) % padlen is not 0:
        return False
    elif paddedAmount is 0:
        return False
    elif paddedAmount <= padlen:
        for i in range(paddedAmount):
            if unpaddedBytes[-1] is not paddedAmount:
                return False
            else:
                unpaddedBytes = unpaddedBytes[:-1]
    else:
        return False
    return bytes(unpaddedBytes)

def main():
    print("running test cases for keysize = 16")
    tests = [b"ICE ICE BABY\x04\x04\x04\x04", b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            b"ICE ICE BABY\x05\x05\x05\x05", b"ICE ICE BABYICEC", b"ICE\x01"]
    expected = [b"ICE ICE BABY", b"", False, False, False, False]
    for i in range(len(tests)):
        res = validatePKCS7Padding(tests[i])
        print("testing bytes", tests[i])
        print("----expected:", expected[i])
        print("----actual:", res)
        if res == expected[i]:
            print(":) test case passed")
        else:
            print(":( test case failed")

if __name__ == '__main__':
    main()
