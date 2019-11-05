import base64




#Set 1 Challenge 1

test = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

testbin = base64.b16decode(test, True)

test64 = base64.b64encode(testbin)

#print(test)

#print(testbin)

#print(test64)

#Set 1 Challenge 2

def fixedXor(bin1, bin2):
    bin1Array = bytearray(bin1)
    bin2Array = bytearray(bin2)
    resultBinArray = bytearray()
    for bit in bin1Array:
        resultBinArray.append(bit ^ bin2Array[0])
        bin2array.pop(0)
    return resultBinArray


testCh21 = "1c0111001f010100061a024b53535009181c"
testCh22 = "686974207468652062756c6c277320657965"

testChXor = fixedXor(base64.b16decode(testCh21, True),
                     base64.b16decode(testCh22, True))

print(base64.b16encode(testChXor))

