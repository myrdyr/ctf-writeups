from PIL import Image

def eca_infinite(cells, rule):
    rulebits = '{0:08b}'.format(rule)
    neighbours2next = {'{0:03b}'.format(n):rulebits[::-1][n] for n in range(8)}
    c = cells
    while True:
        yield c
        c = c[-2:] + c + c[:2]
        c = ''.join(neighbours2next[c[i-1:i+2]] for i in range(1,len(c) - 1))
        c = c[1:-1]

if __name__ == '__main__':
    img = Image.open("30.png")
    im = img.load()
    X,Y = img.size

    RGB = [[''.join(str(im[x,0][i] & 1) for x in range(X))] for i in range(3)]
    for i,e in enumerate(RGB):
        gen = eca_infinite(e[0], 30)
        next(gen)
        for _ in range(Y+1):
            L = next(gen)
            assert len(L) == X
            RGB[i].append(L)

    output = ""
    tmp = ""

    for y in xrange(1,Y):
        for x in xrange(X):
            for rgb in xrange(3):
                if RGB[rgb][y][x] == "1":
                    tmp += str(im[x,y][rgb] & 1)
                    if len(tmp) == 8:
                        output += chr(int(tmp,2))
                        tmp = ""
    while output.endswith("\x00"):
        output = output[:-1]
    print([output])