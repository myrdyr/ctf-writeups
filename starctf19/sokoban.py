from socket import socket
import time
import subprocess

def recvuntil(s, until=b"\n"):
    starttime = time.time()
    data = b""
    while until not in data:
        data += s.recv(1)
        if (time.time() - starttime) > 5:
            print("[-] Timeout!")
            break
    print("[+]", data)
    return data

def send(s, data):
    print("[+] Sending %s", [data])
    s.sendall(data+b'\n')

def storemap(m):
    m = m.replace("8","#").replace("4","@").replace("2","$").replace("1",".").replace("0"," ")
    with open("tmp.map","w") as fd:
        fd.write(m.strip()+'\n')

lookup = {"r":"d", "l":"a", "u":"w", "d":"s"}

def runsolver():
    cur_res = ""
    moves = subprocess.check_output(["./sokoban"]).strip()
    conv_moves = ''.join([lookup[e.lower()] for e in moves.strip()])
    print(moves)
    print(conv_moves)
    return conv_moves

if __name__ == '__main__':

    s = socket()
    s.connect(("34.92.121.149", 9091))
    _ = recvuntil(s, b"one box\n")


    for i in range(25):
        board = recvuntil(s, b"wasd operations):\n")
        print(board)
        board = board[:board.index(b"tell")]
        storemap(board)
        res = runsolver()
        send(s, res)

    print(s.recv(1024))
    print(s.recv(1024))
