from base64 import b64decode as b64d, b64encode as b64e
from Crypto.Cipher import ARC4
import struct

lookup= {0: "Connect",
         1: "Auth",
         2: "Okay",
         3: "ListDir()",
         4: "ChangeDir(s)",
         5: "SetFilename(s)",
         6: "ReadFile()",
         7: "WriteFile(s)",
         8: "Disconnect",
         9: "Connect-OK",
         10: "Auth-Key",
         11: "Algo",
         12: "Success",
         13: "Failure",
         14: "NoOp", # Or above
         }

def parse(raw, dec=None):
    magic  = raw[0:4]
    seqnum = struct.unpack("!Q", raw[ 4:12])[0]
    instr  = struct.unpack("!B", raw[12:13])[0]
    length = struct.unpack("!Q", raw[13:21])[0]
    data   = raw[21:]
    assert magic == b"FILE"
    assert length == len(data)
    payload = b64d(data)
    print([payload, length]) # debug
    if dec:
        payload = dec.decrypt(payload).decode()
    print(seqnum, lookup.get(instr, f"Unk-{instr}"), payload, length)
    return seqnum, lookup.get(instr, f"Unk-{instr}"), length, payload

# part 2
seq = 0
from pwn import *
r = remote("10.0.114.42", 1334)

# Connect
resp = b"FILE" + b"\x00" * (8+1+8)
r.send(resp); parse(resp)
seq, I, length, payload = parse(r.recv())

# Auth
pload = b64e(b"guest:guest").encode()
resp = b"FILE" + struct.pack("!Q", seq) + bytes([1]) + struct.pack("!Q", len(pload)) + pload
r.send(resp); parse(resp)

# Get Auth-Key and Okay it
seq, I, length, payload = parse(r.recv())
print(f"Key: {payload}")
arc4 = ARC4.new(payload)
pload = b''
resp = b"FILE" + struct.pack("!Q", seq) + bytes([2]) + struct.pack("!Q", len(pload)) + pload
r.send(resp); parse(resp)

# Get Algo
seq, I, length, payload = parse(r.recv())

# Send ListDir() and get response
pload = b''
resp = b"FILE" + struct.pack("!Q", seq) + bytes([3]) + struct.pack("!Q", len(pload)) + pload
r.send(resp); parse(resp)
seq, I, length, payload = parse(r.recv(), arc4)

# SetFilename("FLAG_2") 
pload = b64e(arc4.encrypt(b"FLAG_2")).encode()
resp = b"FILE" + struct.pack("!Q", seq) + bytes([5]) + struct.pack("!Q", len(pload)) + pload
r.send(resp); parse(resp)
seq, I, length, payload = parse(r.recv(), arc4)

# ReadFile()
pload = b''
resp = b"FILE" + struct.pack("!Q", seq) + bytes([6]) + struct.pack("!Q", len(pload)) + pload
r.send(resp); parse(resp)
seq, I, length, payload = parse(r.recv(), arc4)