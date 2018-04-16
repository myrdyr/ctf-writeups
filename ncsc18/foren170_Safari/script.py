#"C:\Program Files\Wireshark\tshark.exe" -r safari.pcapng -T fields -e dns.qry.name > dns.txt
sep = "==========================SEPARATOR==========================\n"

def write(fn,s):
    with open(fn,"wb") as f:
        f.write(s)

dns = ''.join([line[:line.index('.')].replace("\\n","") for line in open("dns.txt").readlines() if len(line.rstrip())>0]).replace("\r\n","").decode('base-64')

write("dns.decoded", dns)
write("dns.elf",dns[:dns.index(sep)])
write("dns.zpaq",dns[dns.index(sep)+len(sep):])

#"C:\Program Files\Wireshark\tshark.exe" -r cappy.pcapng -T fields -e data.data > cappy.txt
hexlines = [line.rstrip().replace(":","") for line in open("cappy.txt").readlines() if len(line.rstrip())>0]
d2 = ''.join(hexlines[23:-3]).replace("\r\n","").decode('hex')
write("data.bin",d2)