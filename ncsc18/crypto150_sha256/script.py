import sys
ix = int(sys.argv[1])
import struct
FirstPart = b'\x00\x00\x00 \x96?V\x85Q"\xde\x9b\x82\\\x99S<(\xf7\x852\xfa\x9a\xf6\xa5^=\x00\x00\x00\x00\x00\x00\x00\x00\x00G\n\xa67(\x0c\x85\x9a\xe7:\xa2=\xba\x93\x0c\xeaU4\xabP\x0b\xca\x1d\xc2h\'\xccM\xc9\xd2%\x05Q\xbb\x99Z\xdc\x97]\x17'

import hashlib

res = b'\x00'*2
def force(start, stop):
    for i in range(start, stop):
        MissingInteger = struct.pack('I', i)
        cur = hashlib.sha256(hashlib.sha256(FirstPart + MissingInteger).digest()).digest()
        if res in cur:
            print('Found candidate:', i, cur)

n_threads = 4
step = (2**32)//n_threads
start = ix*step
stop = (ix+1)*step
print('Running from', hex(start), 'to', hex(stop))
force(start, stop)