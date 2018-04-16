import string
ALPHA = string.ascii_lowercase
cipher = "ZVAV18{FeepimqDuLdnEnmetxwgx!!!}".lower()
key = "ohshrahngaoQuieryu".lower()*3

msg = ""
junk = 0
for ix,ci in enumerate(cipher):
    if ci in ALPHA:
        msg += ALPHA[(ALPHA.index(ci) + ALPHA.index(key[ix-junk])) % len(ALPHA)]
    else:
        junk += 1
        msg += ci
print(msg)