strange = open("LoremIpsumStrangeFile.txt").read()
realtxt = open("LoremIpsumReal.txt").read()

sol = ""
for i in range(len(strange)):
    if strange[i] != realtxt[i]:
        sol += chr(ord(strange[i]) ^ ord(realtxt[i]))
print(sol)