from string import printable
KEYLEN = 11
ALPHA = printable + "æøåÆØÅ"
keybytes = []
ciphertext = open("julebord.enc","rb").read()

for key_pos in range(KEYLEN):
    candidates = []
    for key_cand in printable:
        for c_pos in range(key_pos, len(ciphertext), KEYLEN):
            if chr(ciphertext[c_pos] ^ ord(key_cand)) not in ALPHA:
                break
        else:
            candidates.append(key_cand)
    keybytes.append(candidates)

print('|'.join(''.join(e) for e in keybytes))