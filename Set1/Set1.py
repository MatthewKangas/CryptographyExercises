import base64

###Set 1 Challenge 1###

test = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
testbin = base64.b16decode(test, True)
test64 = base64.b64encode(testbin)

#print(test)
#print(testbin)
#print(test64)

###Set 1 Challenge 2###

def fixedXor(bin1, bin2):
    bin1Array = bytearray(bin1)
    bin2Array = bytearray(bin2)
    resultBinArray = bytearray()
    for bit in bin1Array:
        resultBinArray.append(bit ^ bin2Array[0])
        bin2Array.pop(0)
    return resultBinArray


testCh21 = "1c0111001f010100061a024b53535009181c"
testCh22 = "686974207468652062756c6c277320657965"

testChXor = fixedXor(base64.b16decode(testCh21, True),
                     base64.b16decode(testCh22, True))

#print(base64.b16encode(testChXor))

###Set 1 Challenge 3###

##Load in the english character frequency table##
FrequencyTable = {}
rawFreqFile = open("FrequencyTable.txt","r")
FreqFileList = rawFreqFile.readlines()
for line in FreqFileList:
    freqComponent = line.split(",")
    letter = freqComponent[0]
    frequency = float(freqComponent[1].rstrip())
    FrequencyTable[letter] = frequency

##Create search space for possible keys
keySpace = []
start = int('30', 16)
end = int('7a', 16)
for index in range(start, end + 1):
    keySpace.append(index)

##Parse Hex into binary to operate on it
cryptTextHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
cryptTextBin = base64.b16decode(cryptTextHex, True)

def singleCharacterXorDecrypt(cryptTextBin, binCharacter):
    cryptArray = bytearray(cryptTextBin)
    plainArray = bytearray()
    for byte in cryptArray:
        plainArray.append(byte ^ binCharacter)
    return plainArray


##returns a dict with the character frequencies in it as percents of the text
def getTextCharacterFrequency(text):
    textDict = {}
    length = len(text)
    for char in text:
        keys = textDict.keys()
        if char in keys:
            textDict[char] += 1
        else:
            textDict[char] = 1

    for key in textDict:
        textDict[key] = textDict[key]/length

    return textDict

##compares a text to standard english, heavily penalizes non text characters
def compareCharFreq(textDict, referenceDict):
    distance = 0
    for key in textDict:
        variance = 0
        if key in referenceDict:
            variance = abs((textDict[key] - referenceDict[key]))
        else:
            variance = 1
        distance += variance

    return distance

##Driver function to make it work
def SolveSingleCharacterXorCipherCh3():
    closestMatch = "NULL"
    closestDistance = 999
    for key in keySpace:
        plainBin = singleCharacterXorDecrypt(cryptTextHex, bytes(chr(key), 'utf-8')[0])
        plainStr = str(plainBin, 'utf-8').lower().strip()
        distance = compareCharFreq(getTextCharacterFrequency(plainStr),FrequencyTable)

        if distance < closestDistance:
            print("New closest match: " + chr(key) + " " + str(distance))
            closestDistance = distance
            closestMatch = chr(key)

        plainBin = singleCharacterXorDecrypt(cryptTextHex, bytes(closestMatch, 'utf-8')[0])
        plainStr = str(plainBin, 'utf-8').lower().strip()
        print(plainStr)

###Set 1 Challenge 4###

def SolveSingleCharacterXorCipher(cipherText, Fuzzy):
    closestMatch = "NULL"
    closestDistance = 999
    plainStr = ""
    Tries = 0
    for key in keySpace:
        #print("Try Number: " + str(Tries))
        Tries += 1
        plainBin = singleCharacterXorDecrypt(cipherText, bytes(chr(key), 'utf-8')[0])
        plainStr = str(plainBin, 'utf-8').lower().strip()
        #print(plainStr)
        distance = compareCharFreq(getTextCharacterFrequency(plainStr),FrequencyTable)

        if distance < closestDistance:
            #print("New closest match: " + chr(key) + " " + str(distance))
            closestDistance = distance
            closestMatch = chr(key)

    plainBin = singleCharacterXorDecrypt(cipherText, bytes(closestMatch, 'utf-8')[0])
    plainStr = str(plainBin, 'utf-8').lower().strip()
    if(Fuzzy or closestDistance < 8):
        print("Found: " + plainStr)
        print("From: " + str(cipherText))
        print("With key: " + closestMatch)



CipherTextFile = open("Challenge4.txt", "r")
CipherTextList = CipherTextFile.readlines()
for line in CipherTextList:
    #print(line)
    CipherTextBin = base64.b16decode(line.rstrip(), True)
    try:
        SolveSingleCharacterXorCipher(CipherTextBin, False)
        #solution = singleCharacterXorDecrypt(CipherTextBin, bytes('5', 'utf-8')[0])
    except(UnicodeDecodeError):
        tries = 0
        #print("bad key")
