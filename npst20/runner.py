import sys

_ =[exec(f"globals()['r{i}']={i}") for i in range(16)]

class CPU(object):
    def __init__(self, rom, inp):
        self.memory = [0] * 4096
        self.instr = 0
        self.pc = 0
        self.flag = 0
        self.regs = [0]*16
        self.inp = list(inp)
        self.out = b""
        self.running = True
        self.returns = []
        for i, e in enumerate(rom):
            self.memory[i] = e

    def disp(self):
        print("-"*10)
        print('\n'.join(f"r{i} = {hex(self.regs[i])}" for i in range(16)))
        print(f"flag = {self.flag}")
        print(f"PC = {self.pc}")
        print(f"OUT = {self.out}")
        print("-"*10)

    def run(self):
        while self.running:
            self.step()

    def step(self):
        instr = (self.memory[self.pc + 1] << 8) | (self.memory[self.pc + 0] << 0)
        op_class = instr & 0x0F
        op    = (instr >> 4) & 0x0F
        addr  = (instr >> 4)
        value = (instr >> 8)
        arg1  = (instr >> 8) & 0x0F
        arg2  = (instr >> 12) & 0x0F

        if op_class == 0:
            print("STOPP")
            self.running = False

        elif op_class == 1:
            print(f"SETT r{op}, {hex(value)}")
            self.regs[op] = value

        elif op_class == 2:
            print(f"SETT r{op}, r{arg1}")
            self.regs[op] = self.regs[arg1]

        elif op_class == 3:
            print(f"FINN {hex(addr)}")
            self.regs[r1] = (addr & 0xF00) >> 8
            self.regs[r0] = addr & 0xFF

        elif op_class == 4:
            e = ((self.regs[r1] << 8) | (self.regs[r0])) & 0xFFFF
            if op == 0:
                print(f"LAST r{arg1}")
                self.regs[arg1] = self.memory[e]
            elif op == 1:
                print(f"LAGR r{arg1}")
                self.memory[e] = self.regs[arg1]
            else:
                assert False

        elif op_class == 5:
            e = self.regs[arg1]
            n = self.regs[arg2]
            if   op == 0: print(f"OG     r{arg1}, r{arg2}"); self.regs[arg1] &= n              ; print([chr(e),chr(n)])
            elif op == 1: print(f"ELLER  r{arg1}, r{arg2}"); self.regs[arg1] |= n              ; print([chr(e),chr(n)])
            elif op == 2: print(f"XELLER r{arg1}, r{arg2}"); self.regs[arg1] ^= n              ; print([chr(e),chr(n)])
            elif op == 3: print(f"VSKIFT r{arg1}, r{arg2}"); self.regs[arg1] = (e << n) & 0xFF ; print([chr(e),chr(n)])
            elif op == 4: print(f"HSKIFT r{arg1}, r{arg2}"); self.regs[arg1] >>= n             ; print([chr(e),chr(n)])
            elif op == 5: print(f"PLUSS  r{arg1}, r{arg2}"); self.regs[arg1] = (e + n) & 0xFF  ; print([chr(e),chr(n)])
            elif op == 6: print(f"MINUS  r{arg1}, r{arg2}"); self.regs[arg1] = (e - n) & 0xFF  ; print([chr(e),chr(n)])
            else: assert False


        elif op_class == 6:
            if op == 0:
                print(f"LES r{arg1}")
                if len(self.inp) == 0: assert False, "Programmet gikk tom for føde"
                self.regs[arg1] = self.inp.pop(0)
            elif op == 1:
                print(f"SKRIV r{arg1}")
                self.out += bytes([self.regs[arg1]])
            else: assert False, op

        elif op_class == 7:
            e = self.regs[arg1]
            n = self.regs[arg2]
            if   op == 0: print(f"LIK  r{arg1}, r{arg2}"); self.flag = (e == n); print([chr(e),chr(n)])
            elif op == 1: print(f"ULIK r{arg1}, r{arg2}"); self.flag = (e != n); print([chr(e),chr(n)])
            elif op == 2: print(f"ME   r{arg1}, r{arg2}"); self.flag = (e < n) ; print([chr(e),chr(n)])
            elif op == 3: print(f"MEL  r{arg1}, r{arg2}"); self.flag = (e <= n); print([chr(e),chr(n)])
            elif op == 4: print(f"SE   r{arg1}, r{arg2}"); self.flag = (e > n) ; print([chr(e),chr(n)])
            elif op == 5: print(f"SEL  r{arg1}, r{arg2}"); self.flag = (e >= n); print([chr(e),chr(n)])
            else: assert False

        elif op_class == 8:
            print(f"HOPP {hex(addr)}")
            self.pc = addr - 2

        elif op_class == 9:
            print(f"BHOPP {self.flag} {addr}")
            if self.flag:
                self.pc = addr - 2

        elif op_class == 10:
            print(f"TUR {self.flag} {addr}")
            if len(self.returns) > 1000:
                assert False, "For mange funksjonskall inni hverandre"
            self.returns.append(self.pc)
            self.pc = addr - 2

        elif op_class == 11:
            print(f"RETUR {hex(self.returns[-1])}")
            self.pc = self.returns.pop()

        elif op_class == 12:
            print("NOPE")

        else:
            print(f"Invalid instruction {hex(op_class)}")
            self.running = False



        # self.disp()
        self.pc += 2

if len(sys.argv) >= 2:
    rom = open(sys.argv[1], "rb").read()
    inp = b""
    if len(sys.argv) == 3:
        inp = sys.argv[2].encode()
        # inp = bytes.fromhex(sys.argv[2])
else:
    rom = open("spst.s8", "rb").read()
    inp = bytes.fromhex("1729abc3f3b894366b27aff3c51b1dd0d0cec6b199b8def70c92d257ea228ee183ee6524")

assert rom.startswith(b".SLEDE8")
cpu = CPU(rom=rom[7:], inp=inp)
cpu.run()
print(cpu.out)