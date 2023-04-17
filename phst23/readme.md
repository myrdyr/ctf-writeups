# PHST Påskenøtter 2023

Det ble ikke noen NPST-kalender i 2022, og i stedet ble oppgavene flyttet til påsken. Her fikk vi 9 dager med oppgaver, og et par egg å finne underveis.

Som i tidligere writeups, forsøker jeg ikke å belyse alle måter å løse oppgavene på. Kodesnuttene er renskrevet noe etter at oppgavene er løst, slik at det er mulig å forstå hva som skjer, og er ikke nødvendigvis den raskeste måten å løse oppgaven på.

- [Dag 0 - Velkommen](#dag-0---velkommen)
- [Dag 1 - Kongelig brøler](#dag-1---kongelig-br%C3%B8ler)
- [Dag 2 - Ook](#dag-2---ook)
- [Dag 3 - Vårrengjøring](#dag-3---v%C3%A5rrengj%C3%B8ring)
- [Dag 4 - Hvit Boks](#dag-4---hvit-boks)
- [Dag 4 - Hvit Boks - Eggjakt del 1](#dag-4---eggjakt---del-1)
- [Dag 4 - Hvit Boks - Eggjakt del 2](#dag-4---eggjakt---del-2)
- [Dag 5 - Sort På Hvitt](#dag-5---sort-p%C3%A5-hvitt)
- [Dag 6 - Tallknusing](#dag-6---tallknusing)
- [Dag 7 - Kryss og tvers](#dag-7---kryss-og-tvers)
- [Dag 8 - Dataforsking](#dag-8---dataforsking)
- [Dag 9 - Interdepartemental samhandling gir merverdi](#dag-9---interdepartemental-samhandling-gir-merverdi)



## Dag 0 - Velkommen

```
Fra: HR
Sendt: 29.3.2023
Til: Alle_Kyllingagenter
Emne: Velkommen til PHST!

Velkommen til PHST, Kyllingagenter!

Det er flott å se at så mange stiller opp i slike krevende tider. Som dere sikkert har fått med dere så har det vært litt høy temperatur i NPST sine tidligere lokaler. De benytter derfor våre lokaler midlertidig og vi må bistå dem litt fremover.

I år har vi også laget en chatbot som et arbeidsbesparende tiltak! Spør den gjerne om du lurer på noe! Vi er eggstremt stolte av Teknologiavdelingen som har klekket ut dette!

Vi har også en beskjed om å være forsiktige med å dele for mye informasjon. Dere vil være nær plommen i egget med mye sensitiv data. Dere må gjerne samarbeide for å løse problemer, men "need to know"-prinsippet gjelder fortsatt.

Dere kan lese mer om reglene rundt arbeidsforholdet ved å klikke dere inn på "Informasjon" i Start-menyen.

Mellomleder vil ta kontakt med dere snart med nærmere detaljer om arbeidsoppgavene.

Mvh
Hønemor på HR
```

```
Fra: Mellomleder
Sendt: 30.3.2023
Til: {{brukernavn}}
Emne: Velkommen skal du være!

Hei {{brukernavn}}!

Flott å se skikkelig hardkokte agenter som deg i teamet!

Jeg vil ta kontakt hver dag kl. 11 fra og med lørdag med oppgaver til deg. Svar på de epostene med informasjonen du finner. Ting vi ser etter ser ofte slik ut PST{Eggselsior!}, men hold alltid øynene åpne for annet som kan være nyttig!

Mellomleder
```

I starten ønskes vi velkommen, og blir samtidig introdusert for første oppgave, selv om denne bare er verdt like mye som et egg (1 poeng). Flagget her er `PST{Eggselsior!}`.


## Dag 1 - Kongelig brøler

```
Fra: Mellomleder
Sendt: 1.4.2023
Til: {{brukernavn}}
Emne: Kongelig brøler

Hei {{brukernavn}},

godt å se at du finner deg til rette. Her er det første du må løse for oss. Du vil få flere oppdrag til og med søndag 9.4.

Pen GWYN gjorde en skikkelig brøler og ble tatt i forbifarten ved sikkerhetskontrollen på flyplassen. Under armen hadde han et sammenleggbart sjakkbrett med et dokument inni. Dokumentet ser ut til å være kryptert.

Undersøk filen og rapporter funn.

Mellomleder

📎 FEN.txt
```

Inkludert er følgende fil

```
FEN "8/2kqrn2/2b2b2/2nrpp2/2p5/2p5/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2bnrp2/5p2/2pppp2/8/8 w - - 0 1",
FEN "8/1kqrnb2/3b4/3n4/3r4/3p4/8/8 w - - 0 1",
FEN "8/3kq3/3r4/2nb4/3b4/3nr3/8/8 w - - 0 1",
FEN "8/2k2q2/2rn1b2/2bnrp2/2p1pp2/2p2p2/8/8 w - - 0 1",
FEN "8/3kq3/2r2n2/2b2b2/2n2r2/3pp3/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2bn4/2r5/2pppp2/8/8 w - - 0 1",
FEN "8/2k2q2/2rn1b2/2bnrp2/2p1pp2/2p2p2/8/8 w - - 0 1",
FEN "8/8/8/8/8/2kqrn2/8/8 w - - 0 1",
FEN "8/2k2q2/2r2n2/2b2b2/2n2r2/2pppp2/8/8 w - - 0 1",
FEN "8/1k3q2/2r1n3/2b1b3/3n4/3r4/8/8 w - - 0 1",
FEN "8/2kqrn2/2b2b2/2nrpp2/2p2p2/2p2p2/8/8 w - - 0 1",
FEN "8/2k2q2/2rn1b2/2bnrp2/2p1pp2/2p2p2/8/8 w - - 0 1",
FEN "8/2k5/2q5/2r5/2n5/2bbnr2/8/8 w - - 0 1",
FEN "8/3k4/3q4/3r4/3n4/3b4/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2b1nr2/2p2p2/2pppp2/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2bn4/2r5/2pppp2/8/8 w - - 0 1",
FEN "8/8/8/8/8/2kqrn2/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2bnrp2/5p2/2pppp2/8/8 w - - 0 1",
FEN "8/1kqrnb2/3b4/3n4/3r4/3p4/8/8 w - - 0 1",
FEN "8/3k4/3q4/3r4/3n4/3b4/8/8 w - - 0 1",
FEN "8/2k5/2q5/2r5/2n5/2bbnr2/8/8 w - - 0 1",
FEN "8/2k5/2q5/2r5/2n5/2bbnr2/8/8 w - - 0 1",
FEN "8/3k4/3q4/3r4/3n4/3b4/8/8 w - - 0 1",
FEN "8/2k2q2/2rn1b2/2bnrp2/2p1pp2/2p2p2/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2b1nr2/2p2p2/2pppp2/8/8 w - - 0 1",
FEN "8/2kqrn2/2b5/2bn4/2r5/2pppp2/8/8 w - - 0 1",
FEN "8/2kqr3/2n2b2/2bnr3/2p1p3/2p2p2/8/8 w - - 0 1",
FEN "8/2kq4/3r4/3nb3/3b4/2nr4/8/8 w - - 0 1"
FEN "pBrpnRrB/nPpbrBPP/rRbnpNBR/pBNBPrPP/pNrnNpPR/rPRBbNrB/bBPpNPpn/rPRbpRrN w - - 0 1"
FEN "nRrBBRPN/bBPNnrPP/rRPnRpNr/rNPbnprB/pPNbPbRP/rBRpNrBP/rNBRrPRp/nPBrbnrN w - - 0 1"
FEN "pPNBrbPp/bNBnPnrP/rNRbbprB/bPBrBPBr/pBNRrNnp/pPBnpPpP/rNBRnrBn/bNPBRRnN w - - 0 1"
```

FEN er en forkortelse for Forsyth–Edwards Notation, og brukes for å beskrive posisjonene til alle brikkene på et sjakkbrett. Det går an å kopiere det mellom anførselstegn fra hver linje til f.eks. [Dcode](https://www.dcode.fr/fen-chess-notation) for å se hvordan brettet ser ut. Her ser vi fort at det skrives bokstaver med sjakkbrikker, og at de staver ut `PST{NOEN_UVANLIGE_STILLINGER}`. De tre siste linjene passer derimot ikke inn, og de har fylt hele brettet med brikker. Ved å analysere disse nærmere ser vi at sorte og hvite brikker (differensiert med store og små bokstaver) står for 0 eller 1, og at det binære til slutt danner en streng og årets første egg; `EGG{Kule_sjakkvarianter}`.

Et script for å automatisere begge prosessene kan være følgende
```python
# Flagg
def parse_fen(fen):
    board = [list(" "*8) for _ in range(8)]
    for y,f in enumerate(fen.split("/")):
        x = 0
        for c in f:
            x += int(c) if c.isnumeric() else 1
            if x >= 8: continue
            board[y][x] = "#" if c in "kqrnbp" else " "
        board[y] = ''.join(board[y])
    print('\n'.join(board))
                

lines = [e[e.index('"')+1:e.index('w')-1] for e in open("FEN.txt").read().splitlines()]
for line in lines[:-3]:
    parse_fen(line)
    
# EGG
from Crypto.Util.number import long_to_bytes
egg = '/'.join(line for line in lines[-3:])
print(long_to_bytes(int(''.join([str(int(e.isupper())) for e in egg if e!= "/"]),2)).decode())
```

## Dag 2 - Ook

```
Fra: Mellomleder
Sendt: 2.4.2023
Til: {{brukernavn}}
Emne: Ook?

En orangutan mistenkt for samarbeid med sydpolare aktører har blitt arrestert. Han forsøkte å spise noen dokumenter før vi fikk tatt beslag i dem, men vi klarte å redde dette. Dessverre skjønner vi ikke et pip.

Se om du finner ut av noe. Ook?

Mellomleder

📎 Ook.txt
```

Den vedlagte filen inneholder instruksjoner til det esoteriske programmeringspråket "Ook!", som mange kanskje kjenner igjen fra før. Det er egentlig bare et annet esolang kalt "Brainfuck" i forkledning, hvor hvert par med "Ook+symbol" danner en av de 8 instruksjonene i "Brainfuck". Det finnes flere interpretere for Ook! online, så det er bare å lime inn koden [her](https://www.dcode.fr/ook-language) og kjøre den. Flagget er `PST{A1m05tL1k3Bra1nfuck}`.

## Dag 3 - Vårrengjøring

```
Fra: Mellomleder
Sendt: 3.4.2023
Til: {{brukernavn}}
Emne: Vårrengjøring

Mellomleder ba meg se på dette bildet i går, men nå har jeg stirra på det til jeg blir skjeløyd og finner ingenting! Kan du ta over saken?

Tastefinger

PS: Om du trenger en rubber duck for å debugge noe kan du låne stegosauren som står på plassen min.

📎 bilde.png
```

Det vedlagte [bildet](3-bilde.png) er et såkalt stereogram, noe det hintes til i oppgaveteksten og inni et av farge-lagene på bildet. Ved å legge en kopi av bildet oppå seg selv, og forskyve dette bildet, så vil det komme et tidspunkt hvor XOR av de to lagene har mye lavere entropi enn ellers. Det sammenfaller også med hvordan stereogrammet ser ut. Min løsning så [sånn her ut](3-stereogram.png). Flagget er `PST{Med_øyne_i_kryss}`.

I tillegg hadde det grønne fargelaget i bildet [denne informasjonen](3-Green_0.png) hvor det hintes til XOR. Ved å XORe sammen det grønne og blå laget får vi [enda et egg](3-egg.png) `EGG{EGGSOR}`.


## Dag 4 - Hvit Boks

```
Fra: Mellomleder
Sendt: 4.4.2023
Til: {{brukernavn}}
Emne: Hvit Boks

NPST har hentet frem et beslag de tror kan ha en sammenheng med hendelsen sist jul. Beslaget ble tatt av en hvit boks med "lappes dualistisk" tusjet på. NPST har sett på dette fra alle kanter, men ikke funnet ut av noe.

Her må det nok en kylling til!

Mellomleder

📎 hvitboks
```

Filen `hvitboks` er en relativt stor (~35MB) x86_64 ELF som ber om et passord. Analyserer denne i IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  char *v4; // rcx
  uint64_t hash; // rdx
  unsigned __int8 v7; // [rsp+0h] [rbp-58h] BYREF
  char v8; // [rsp+1h] [rbp-57h] BYREF
  unsigned __int64 stack_cookie; // [rsp+48h] [rbp-10h]

  stack_cookie = __readfsqword(0x28u);
  sub_406180("Passord: ", argv, envp);
  if ( sub_40A7F0(&v7, 0x40, off_26DFAB8) )
  {
    v3 = v7;
    if ( !v7 )
      goto LABEL_9;
    v4 = &v8;
    hash = 5381LL;
    do
    {
      ++v4;
      hash = v3 + 33 * hash;
      v3 = *(v4 - 1);
    }
    while ( v3 );
    if ( hash == 0x6666B3AC68725287LL )
LABEL_9:
      puts("Feil passord.");
    else
      decrypt_print();
  }
  if ( stack_cookie != __readfsqword(0x28u) )
    stack_fail();
  return 0;
}
```

Programmet leser inn input fra stdin, og kjører en hash-funksjon kalt DJB2 på inputen (inkludert newline). Hvis resultatet er 0x6666B3AC68725287 (mod 2^64) så kaller den en funksjon som dekrypterer og skriver ut passordet, ellers skrives det ut `"Feil passord."` og returneres. Den enkle løsningen på denne er å åpne programmet i en debugger, sette breakpoint på sjekken, og så invertere den. Ved å se på assemblyen for koden så finner vi et fint punkt å sette breakpoint på. Dette gjør vi etter compare mellom rdx og rax, hvor zero-flagget (ZF) blir satt hvis rdx==rax (korrekt passord).

```
.text:00000000004016B7                 jnz     short loc_4016A0
.text:00000000004016B9                 mov     rax, 6666B3AC68725287h
.text:00000000004016C3                 cmp     rdx, rax
.text:00000000004016C6                 jz      short loc_4016E6           <------------------
.text:00000000004016C8                 xor     eax, eax
.text:00000000004016CA                 call    decrypt_print
```

Inne i GDB gjør vi dette med følgende kommandoer. Binaryen er heldigvis ikke kompilert med PIE, så vi kan bruke adressene rett fra IDA.

```
b *0x4016c6
run
<skriv inn et random passord>
set $eflags |= (1 << 6)
c
```

og outputen er
```
Gratulerer! Det var riktig passord, her er flagget:
PST{MANNEN_SOM_LEKTE_MED_MINNET}
[Inferior 1 (process 21) exited normally]
```

og så kan vi vel egentlig stoppe her, men jeg dro på jakt etter egg.

### Dag 4 - Eggjakt - del 1
Hva skjer inni `decrypt_print`? Koden ser noenlunde slik som det her ut. Den implementerer [Whitebox AES, med denne implementasjonen](https://github.com/JeanGa128/AES-whitebox), hvor man kan konvertere en nøkkel til et sett med tabeller og mellomkalkulasjoner som lar en kryptere og/eller dekryptere uten å få kjennskap til nøkkelen. Dette gir også mening med tanke på navnet til oppgaven. I en god Whitebox-implementasjon skal en "angriper" ha tilgang til en programfil, og ikke få til å finne ut hva nøkkelen er.

```c
__int64 decrypt_print()
{
  __m128i _p0; // xmm0
  unsigned __int8 *flag; // rbx
  unsigned __int8 v2; // di
  _BYTE expandedKey[176]; // [rsp+0h] [rbp-128h] BYREF
  __m128i v5; // [rsp+B0h] [rbp-78h]
  __m128i hmm; // [rsp+C0h] [rbp-68h] BYREF
  _BYTE key[16]; // [rsp+D0h] [rbp-58h] BYREF
  __m128i p0; // [rsp+E0h] [rbp-48h] BYREF
  __m128i p1; // [rsp+F0h] [rbp-38h] BYREF
  char v10; // [rsp+100h] [rbp-28h] BYREF
  unsigned __int64 v11; // [rsp+108h] [rbp-20h]

  v11 = __readfsqword(0x28u);
  hmm = _mm_load_si128(&init);
  *key = 0LL;
  sub_401E30(&hmm, key);
  _p0 = _mm_load_si128(&block_0);
  flag = &p0;
  p0 = _p0;
  p1 = _mm_load_si128(&block_1);
  expandKey(expandedKey, key);
  v5 = 0LL;
  AES_decrypt(&p0, expandedKey);
  v5 = _p0;
  AES_decrypt(&p1, expandedKey);
  p1 = _mm_xor_si128(_mm_load_si128(&block_0), p1);
  puts("Gratulerer! Det var riktig passord, her er flagget: ");
  do
  {
    v2 = *flag++;
    printf(v2);
  }
  while ( flag != &v10 );
  if ( v11 != __readfsqword(0x28u) )
    stack_fail();
  return printf('\n');
}
```

Kort fortalt så lastes det inn en transformert nøkkel, og denne brukes til å initialisere noen ting som AES trenger senere. Selve flagget ligger kryptert i `block_0` og `block_1`, her representert som 128bit-tall som lastes inn via SIMD-registere. Etter dekryptering, så XORes den dekrypterte versjonen av blokk 1 med den krypterte versjonen av blokk 0. Dette tilsvarer AES i CBC-modus hvor IV (initialization vector) er 0. Selve dekrypteringsfunksjonen er ganske stor, og ser egentlig ut til å hovedsaklig slå opp i whitebox-tabellene og permutere dataene noe. Den største magien finner vi i `sub_401E30`, hvor den transformerte nøkkelen på et eller annet vis havner.

Selv om det var mye komplisert, så la jeg merke til noe data på adresse 0x474060 som lignet veldig på RCON (round constants) for AES. Disse går også inn i expandKey-funksjonen og ser ut til å initialisere en struct jeg kalte `expandedKey` som er 176 byte lang. Inne i `AES_decrypt` ser jeg en referanse til expandedKey hvor det ser ut til at den brukes som en normal round constant. Av å ha studert [AES key schedule](https://en.wikipedia.org/wiki/AES_key_schedule) vet jeg at nøkkelen ligger åpent helt i starten av den ekspanderte nøkkelen.

Setter et breakpoint igjen på starten av `expandKey(_BYTE *expandedKey, char *key)` og så inspiserer jeg andre argumentet.

```
b *0x401830
run
<input gyldig pw her eller patch>
pwndbg> x/2gx $rsi
0x7fffffffe400: 0xcb2fb74333369238      0xd43778d4e0d97ae5
```

Er dette nøkkelen da? La oss verifisere. Henter ut block_0 og block_1 først, passer på endianness, og så kaller vi den `ct`.

```python
from Crypto.Cipher import AES

ct = bytes.fromhex("3a59d1ce4087bd7a4e9d1526f09247cc2a50f0cd13fbc4fa1b1827b5d2e298ac")
key = bytes.fromhex("3892363343b72fcbe57ad9e0d47837d4")
print(AES.new(key, AES.MODE_CBC, iv=bytes(16)).decrypt(ct))
```

```bash
root@d591742f53fb:/ctf/work# python3 solve.py
b'PST{MANNEN_SOM_LEKTE_MED_MINNET}'
```

Jessda, det var nøkkelen. Tviler litt på at det er meningen at det skal være så lett å hente ut nøkkelen fra implementasjonen. Under testing fant jeg også [en annen implementasjon](https://github.com/Gr1zz/WhiteBoxAES) som hadde en lignende feil. Der var det mulig å finne nøkkelen inni Tbox, kun obfuskert med en enkel AES ShiftRows. Hadde ikke dette fungert heller, så hadde neste steg på lista vært å bruke side-channels til å angripe tabellene direkte, ved å modifisere de på strategiske måter og se etter bytes som ikke endrer seg. Her finnes det flere verktøy fra før av.

Men jeg fant ingen egg. Kanskje det finnes et gyldig passord som også er et egg da?

### Dag 4 - Eggjakt - del 2
DJB2-hashen er dessverre lossy. Den shifter med ca. 5 bits for hver input, noe som gjør at flere bytes kan overlappe, og dermed får man flere inputs som gir samme hash. I tillegg wrapper den rundt når den når 64 bits, og hvis inputen var lengre enn det så mangler vi en del informasjon. Det er enkelt å se at siden målet (0x6666B3AC68725287) ikke er kongruent med 10 mod 33 så var ikke den siste byten som ble hashet en newline, siden newline (`\n`) har verdien 10 mod 33. Inputen vår har derimot alltid med en newline (inntil 64 tegn i alle fall), så det må ha wrappet rundt på et tidspunkt. Vi kan wrappe tilbake igjen ved å plusse på `0x10000000000000000` et utall ganger, og så hele tiden sjekke om verdien er 10 mod 33. Hvis den er det, forsøker vi å finne en løsning til hashen via bokstaver i det vi anser som "printable" ASCII, altså bokstaver, tall, og et knippe ulike tegn. Jeg tok også med "ÆØÅæøå" for å være sikker. Etter veldig mye brute-forcing, og en mer spesialsert brute-force etter passordet på formatet `EGG{...}\n` måtte jeg medgi at det ikke var noe å spennende å finne. Jeg fant flere hundre tusen passord som virket, men ingen av de så særlig spesielle eller interessante ut. Her er et par eksempler på de jeg fant:

```
root@d591742f53fb:/ctf/work# ./hvitboks
Passord: 26fbEEmdlErg4yv
Gratulerer! Det var riktig passord, her er flagget:
PST{MANNEN_SOM_LEKTE_MED_MINNET}
root@d591742f53fb:/ctf/work# ./hvitboks
Passord: cx2wr4d4tpu6n4e
Gratulerer! Det var riktig passord, her er flagget:
PST{MANNEN_SOM_LEKTE_MED_MINNET}
root@d591742f53fb:/ctf/work# ./hvitboks
Passord: lr}eabc5cE}i02m
Gratulerer! Det var riktig passord, her er flagget:
PST{MANNEN_SOM_LEKTE_MED_MINNET}
root@d591742f53fb:/ctf/work#
```

Jeg brute-forcet lenge, men ikke lenge nok til å finne en input som så "eggete" ut. Fikk etterhvert bekreftet at det ikke var mer å finne, ettersom DASS lekket alle eggene via en feil i APIet. Denne feilen fikk også alle eggene til å råtne og gi 0 poeng.


## Dag 5 - Sort På Hvitt

```
Fra: Mellomleder
Sendt: 5.4.2023
Til: {{brukernavn}}
Emne: Sort på Hvitt

Det har blitt avdekket et nettverk av sydpolare illegalister som kommuniserer mellom hverandre i det åpne, men ingenting av det de sier gir noe mening. Vi mistenker at dette har sammenheng med brannen i Jule NISSEN sitt verksted.

Mellomleder

📎 rapportering.txt
```

Filen `rapportering.txt` inneholder en tekst med veldig mystisk spacing. Det veksles mellom å bruke space og tab. Jeg gjenkjenner dette som enda et esolang kalt `whitespace`, hvor tab, space og newline brukes for å skrive koden. Alle andre tegn ignoreres, så det er ikke nødvendig å gjøre noe med teksten for [å kjøre den](https://www.dcode.fr/whitespace-language). Svaret er `PST{h1dd3n_1n_pl41n_s1ght}`.


## Dag 6 - Tallknusing

```
Fra: Mellomleder
Sendt: 6.4.2023
Til: {{brukernavn}}
Emne: Tallknusing

Så mange tall har ikke jeg sett siden jeg var i niende eller tiende klasse! Jeg tror jeg heller holder meg til Sudoku.

Men! Noen må fortsatt finne ut av dette. Kan du?

Mellomleder


101 148  35 103  80 146 102  72  76
 80 103 102 148  76  72 101  88 146
 76  72 146 101  88  35 148  35  80
148  88  76  72 101 103  80 146 102
 35  80  72 102 148  88 103  76 101
103 102 101  76 146  35  35 148  88
 88 146 148  80 103 101  76 102  72
 72  35 103 146 102  35  88  80  35
102  76  80  88  72 148 146 101 103

PS: Jeg er i en annen base til i morgen. Om du trenger noe så ta kontakt med Tastefinger.
```

For denne oppgaven er man nødt til å skjønne alle hintene. Det hintes til "base", "ni", og "sudoku". Ved å se på tallene og tolke de som base-9 og konvertere til ASCII så får man en del repeterende tegn. Hvis man ser på disse på samme format som de originale tallene, så ser man noe som ligner på et sudoku-brett. Spacing er lagt til for formatering.

```
R}  | TH{ | SAE
HTS | }EA | RP{
EA{ | RP  | } H
--- + --- + ---
}PE | ART | H{S
 HA | S}P | TER
TSR | E{  |  }P
--- + --- + ---
P{} | HTR | ESA
A T | {S  | PH 
SEH | PA} | {RT
```

Ved å se på tegnene som er i bruk (`AEHPRST{}`) og hvilke som mangler i hver rute, så mangler tegnene `PST{HARE}` om man starter øverst til venstre og leser fra venstre mot høyre, linje for linje nedover. Dette er også flagget.


## Dag 7 - Kryss og tvers

```
Fra: Mellomleder
Sendt: 7.4.2023
Til: {{brukernavn}}
Emne: Kryss og tvers

Disse filene dukket opp i en sak, og de ser noe mystiske ut. Jeg tror vi ser på dette helt feil vei, du må nok ta en titt her!

📎encoder.py

Det er best at du ikke sitter på gjerdet, og ser på saken for oss. Hvis du finner innholdet i 📎flagg.bin, så kommer det nok til å gå på skinner!
```

Koden tar litt tid å fordøye, men prinsippet er enkelt

```python
def forward_engineering(flagg):
    p1 = int("000".join([str(ord(c)) for c in flagg[:math.ceil(len(flagg)/3)]])) ^\
        int("000".join([str(ord(c)) for c in flagg[math.ceil(len(flagg)*2/3):]]))

    p2 = int("000".join([str(ord(c)) for c in flagg[math.ceil(len(flagg)/3):math.ceil(len(flagg)*2/3)]])) ^\
        int("000".join([str(ord(c) << 2) for c in flagg[math.ceil(len(flagg)*2/3):]]))

    p3 = p1 ^ int("000".join([str(ord(c)) for c in flagg[math.ceil(len(flagg)*2/3):]]))

    jx = base64.b64encode("123456789".join([str(p1), str(p2), str(p3)]).encode("ascii"))

    with open("encoded.bin", "wb") as file:
        file.write(jx)
```

Flagget deles i 3 biter, la oss kalle dem `b1, b2 og b3`.

- Den utdelte verdien `p1` er hver bokstav i `b1` som tall, separert med tre nuller. Til slutt er det xoret med `b3`, som er representert på samme måte.
- `p2` er `b2` (også separert med nuller) xoret med `b3`, men her er hver verdi er ganget med 4 før separatoren er lagt på.
- Siste verdi `p3` er hele `p1` xoret med `b3`, igjen separert med nuller.
- Alle verdiene `p1..p3` blir til slutt base64-encodet etter å ha blitt separert med strengen "123456789".

Oppsummert har vi
```
flagg = b1 + b2 + b3
p1 = b1 ^ b3
p2 = b2 ^ (4*b3)
p3 = p1 ^ b3 = b1 ^ (b3 ^ b3) = b1 ^ 0 = b1
```

hvor tegnet `^` representerer XOR-operasjonen, som også er sin egen invers.

Vi starter med å base64-dekode og splitte stringen på "123456789" for å få igjen `p1..p3`. Siden `p3` er lik `b1` har vi allerede fått ut første del av flagget. Ved å XORe `b1` med `p1` får vi `p1 ^ b1 = (b1 ^ b1) ^ b3 = b3`, og dermed vet vi også siste del av flagget. For å få ut `b2` kan vi nå regne ut `4*b3` slik som i koden og XORe resultatet med `p2`.

```python
import base64, math

p1, p2, p3 = map(int,base64.b64decode(open("flagg.bin").read()).decode().split("123456789"))

b_1 = bytes(map(int,str(p3).rsplit("000")))
b_3 = bytes(map(int,str(p1^p3).rsplit("000")))
b_2 = bytes(map(int,str(p2 ^ int("000".join([str(c << 2) for c in b_3]))).rsplit("000")))


print(b_1 + b_2 + b_3)
```

Koden over skriver ut `ZigZag PR_cr__ew}S{alFnee_nfnltntitTie_eii_s`. Dette ligner ikke akkurat på et flagg, men vi kan se at de korrekte bokstavene er inni der. Oppgaveteksten har flere hint som `sitter på gjerdet` og `gå på skinner` for å skjønne hva som skjer videre. Dette er nemlig [Rail Fence (Zig-Zag) Cipher](https://www.dcode.fr/rail-fence-cipher) hvor teksten man skal kryptere skrives i sikk-sakk, og så leser man den linje for linje etterpå. For å dekode teksten trenger man å vite hvor mange "skinner" man sikk-sakket mellom, og hvilken skinne man startet på. Ved å fjerne "ZigZag " i starten og dekode som rail fence med nøkkel `3,0` får jeg `PST{Rail_Fence_er_en_fin_liten_twist}`. Merk at man må krysse av for å beholde symboler for å få en korrekt dekryptering.


## Dag 8 - Dataforsking

```
Fra: Mellomleder
Sendt: 8.4.2023
Til: {{brukernavn}}
Emne: Dataforsking

Hei {{brukernavn}},

De siste årene har man på Påskeøya drevet med datainnsamling på påskekyllingene.

📎innsamlet.csv

Hensikten er å kunne kategorisere kyllingene i to typer kyllinger, den ene egnet for EGGSamling, og den andre mulig egnet for å flY. Kanskje du kan bruke dette til noe? Akkurat hva som skal gjøres med dataen er vi litt usikre på, men noen mener at den kanskje bør visualiseres.
```

CSV-filen inneholder en rekke data

```csv
vingespenn,gjennomsnittlig antall egg samlet per dag,kyllingtype
1,0,'0'
2,0,'0'
3,0,'0'
4,0,'0'
5,0,'0'
6,0,'0'
7,0,'0'
8,0,'0'
9,0,'0'
...
```

Hvor `vingespenn` teller fra 1 til 56, og så starter den å telle på nytt med `gjennomsnittlig antall egg samlet per dag` økt med 1 for hver runde. Den siste verdien er for det meste `'0'` i starten, men starter å variere mellom `'0'` og `'1'` etterhvert. Oppgaveteksten hinter til at man skal visualisere, og skriver også `EGGS` (uttales nesten som 'x'), og `Y`. Så løsningen er å bruke de to første tallene som X og Y og `kyllingtype` angir om en pixel er svart eller hvit. Alternativt går man til [dcode Binary image](https://www.dcode.fr/binary-image) og limer inn siste kolonnen der med angitt bredde på 57.

![](8-dcode-image.png)

Løsningen er `PST{EGGESKALL}`


## Dag 9 - Interdepartemental samhandling gir merverdi

```
Fra: Mellomleder
Sendt: 9.4.2023
Til: {{brukernavn}}
Emne: Interdepartemental samhandling gir merverdi

Teknikere fra direktoratet for høytidsteknologi har bistått Jule NISSEN med å hente ut informasjon fra skadede systemer på verkstedet som kan være relevant for etterforskningen. Dessverre har de sendt det over på en sikker måte, så det er litt usikkerhet rundt hvordan vi skulle få sett på det.

Her trenger vi en skarp Kyllingagent til å se på det!

Mellomleder

📎 Vedlegg_1.txt

📎 Foelgeskriv.txt

📎 Do-ChickenCrypt.ps1

📎 Invoke-Svadacrypt.ps1

📎 InformasjonsBasseng.7z
```

Den siste dagen med oppgaver slenger ganske mange ting i fanget vårt med en gang. Vedlagt har vi et "følgeskriv", som ikke virker særlig interessant. Filen `Vedlegg_1.txt` inneholder mange linjer med tall som er 1-2 sifre. `InformasjonsBasseng.7z` er passord-beskyttet, og passord for 7z er relativt treigt å brute-force i forhold til mange andre arkivformater. Her må vi nok ha et passord. Til slutt har vi to ulike PowerShell-script å analysere.

### Do-ChickenCrypt.ps1

Dette humoristiske scriptet gjør XOR med en byte 9000 ganger. Problemet er at det er samme byte brukt på alle bokstavene. Resultatet er like god sikkerhet som om man bare hadde gjort det én gang. Ved å anta at `Vedlegg_1.txt` inneholder output fra dette scriptet, så tar vi tallene, konverterer fra decimal til ascii, og gjør en 1-byte XOR brute-force. Resultatet er strengen `OffentligForvaltningSikrerKunnskapsforankringOgKonvergensAvProsessorientertEffektiviseringRealiseres`. Det er også noe morse-kode i scriptet som gjemmer egget `EGG{0_clucks_given}`.


### Invoke-Svadacrypt.ps1

Neste script dekoder noe base64 og lagrer det som bildet [instructions.jpg](instructions.jpg). Etter dette, så venter det på at noe skal havne i clipboard, før det så hashes med MD5 og forsøkes som et passord til å dekryptere en [SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-7.0). Tester strengen fra forrige script og får at det er en match! Bak den krypterte strengen venter en ny streng: `FagseminarOmVedtakAvStrategiskImplementringsplanForTverrfagligHorisontalSamhandlingVilAnbringeIterativSynergi`. Denne viser seg å være passordet til `InformasjonsBasseng.7z`.

### InformasjonsBasseng.7z

Innholdet i arkivet er kun filen `InformasjonsBasseng.db`. Dette er en SQLite-database som kan åpnes i mange ulike programmer for å inspisere innholdet. Det er ikke så mye å gå gjennom i denne, men det er to interessante tabeller med noe uleselig tekst.

Den første ligger i tabellen `data` med feltene `time` og `keys`. Henter ut bare `keys` og legger disse på linje.

```
PEFRMTDJK9WS184KG1NH8CT8AP3HERH306848QURPJNV7PX2FXYBZG4NB8OAE8DV
ISDGQRA8KALM1OTUCS5272ECAH427F1E25FSSQF7F5LCSE0RLDPWGDQTZYD44G30
I2T6LBJJBA6FIN6M9WA0B353OR720DGMWHZPW2SVDQ9T1QZDF7B2DW1OZ38DRJBE
WKE{PBVCBWDD29FR5KK90VC9J3NCZ2CMBGGFNOVV82UW1LDIJWUJI7K4Q0EDMX4M
I5HFP87V73ZRA7R3E37BTU7UKJ1DZ0TMAT1NZ0JTVRJHXMBJUIPHN37WWBWNWOCM
FLFW3o39BGQ69TL33EZ2HZRHRILIJQBSJ44KXXQ1CO2K7THY0VJWL9IB2DZPCP45
1H0E0AwNQGTAY4WE43538H6FPNEL0MDWVZ0DK97MHU2L6G5BKU28ULMYW5HDXYUG
MVXDFXDe01HQQTMZCWCIX1VMUXGYL7IRQ2880B8QYGS0L3LAS0SXQWPYE7K31F5J
6FRYNFSTr5RKX5W5NI2B2WM0XUWQIOV4HOZHGNEV7IANOSYH85DBC7RBSIFI6U7O
VPWE3G5WEsE1QI1J9M5CN37XSH1HF5TGCWS9U3DXFXHN13N4CT2LTFMI8JBUVL2Y
KXH3PQANXMhQG4967ADDVNKNQUNKWXLGEGHAPBLTB77K5U8ZTHHSWKLHSTIMODA5
1YJNCGF9R8QeI2B7LDXU6LWCKU1Y3AGU1WCQ2WMBUQTUOT32WL3XX4Z4Z0AXAMHA
3AGZL2KP03VMlZYMZZ63HW1ULD9ZN8K9EEXNHM6EKBHEAWLWWQCV02S8KKHC6N5Q
KRGV5J75G8ALBl9S0V9C1H47BCFWLV9MUGTP84YU2SHZ2EHEA1HY96UB8P28B9W1
UAFWG6WRIE7VHSiCJH1PKDU1P9667GSIE3WYYAVW3J8T74R437QFA9EID8TRSI7D
M216LOVH2SB97NKgIN17P30HD0PBUTJN86GHW6SNXSYL1MUAPKRRA4UZOHP8STCU
RWHB0B5TAVQ11O38_9SF0BKXXT3U1RMY8SCCU7ARJGVNXGOS66YL95O4TC21X9M8
TQDKZQA5QXCD8SVJEgGGXZYL10UFQOSQAY985OJSYWY033GPNFWO2D4GQDVXMT5X
V2L7KKM5XBRFIU1EJYrR1AYXGY9W09S3PXU9GST2DKITHZEV4CX0RAP7RT7G8WZU
13TMIUNBU59AV9KD98Ru2J4YPOQ111POQD38KB7MJW9D6O8D52RD54COOIM3RYXK
FPA2L1YOKMJX9056G65VnRQP6TV5HHA8GD9KCGVRAZR5LF1WNF97IJ62MVWHO72N
MFA669HYX5C3NZAX00XILnACZ0DLVW8QM45GNPI5A42LDJ1VCC1RZIC4MCO45PNB
EFUUK6601XVOKNJKGBWEX6_875H3A7JDQPM8RRDYERQBUSHEOCGVT9Q6ZIVN4CNI
B887QMN4PATWL49LEVDI0OStE0CND3SK140BGZP8TKGROF1NQ94SYCT85GFNZMTQ
A9H3W1SAFTQE0HMYIPK48L24iSSECKTJVPAI4Q1SZ05SNQ2J14GWUWFWS48NMC30
02I15SKSC8FU3VSVEUU0J7LG0l98CVQ1N48UQ8KZDZLP8Q3OC5BL40DNGSUITMEE
H0DTHEB8CIWY1RCFRHTESF48KN_ZW7J73LX0RIM2KYTIOLXJECVA8ABSE97CQLJT
BWZVY2SJYUWNNHLTG6M9AOIE3WAm2EY3BWJAKXBCW54NSKTQW12WUD4GZJ8I2HA1
2Z4BBJRPF5YOFB8EHHS5QJXHXV3PiEG0FG0D6X7D32I7GPZKKESZ22ZUXAI4YO7R
SBF80U7K7C16Z5M1XHKCORTNKNNIUsCZC834VYML85S5NGWTVR33AB15P7CJ6SI9
H1R9L43RSLZTXKFJEI65UM439KWP46t8POSZIG6T78JYNXYPHMBBT1VE43RUQWNT
M03I9Y9J0L0NOO386992DINWM8L3ITIaHYVLB8USK0T9TFQ0KHTZ2565NQNES6ZZ
ZQC8B1DDFZUPFWYJPVGOO98CSFKL3A52nT5QT6WLIHHRWY06347GQL3HGR7T6B0K
9G34L9Q2MSI628LRTG7OAFOKJ4QTMJ22Gk4FOIMCJHQNP5ZYI5NBLXQSRAX68VYY
ZOJ9TH1HVP429LPTN0OUUIY97ZL8X92DRMeDFGC2J32L6KZYZ9L8WLQPY3UL0CD0
O06YYE1CDWFXVM7Z30PH46YYN51ZA8YOXBO}J8VIIBRFN6XU9JX0MHP526QLP3T3
```

Ved å lese fra øverste hjørne til venstre og ned langs "diagonalen" kan man lese ut et flagg. Alternativt kan man scripte det.

```python
lines = open("data.txt").read().splitlines()
print(''.join(lines[i][i] for i in range(len(lines))))
```

Flagget er `PST{Powershellig_grunn_til_mistanke}`.

I tillegg ligger det en tabell som heter `informasjon` i databasen

```
XV0TA7TF0E8PIZ6GFT3BJ}4UR8EAJRFO97W14II0SR5QYZYDA2S2XWHKKML6N2EO
TUABEU88KKW16GZ9MX52sYMX7DB4QBQFGWHHQS7CXUMCN5IS5S3L445FQZL9FVKF
67UW1891TO9YD1ZBK9Nn8JUL4ADQP4VT1G76LFA46S1XYKKR5ZDQ6IK1V43DWYJZ
ZYEXMWL4Z24JRH3TUNeZQEHEDB5AY1OSG9NXGJFYFXLY1EXIZBTLR34SPPWXY6Z6
RXA16PB9BZ264SUERkZKEJD3K9TOQ1RUC1C7V4FBM4ECTK5TCCITZD303Z1AF1PZ
X7OE84SKIS6W2NL2cUCXTNTU0HO0F3U8QNE0JQQP3GKX33F71G34OD5W3BIO0I0Q
MQRGSK8TVPBX0HIiATMAUTYIOEA81BSLU7CUVE93Y1T4MRJZV5Y5SNSO7TQESBO0
TUMBWRLRA9CJXLhZK0A4D7GLQ1BC350VB1XVBN1AZ2LUR4QZOHJEBWCNBRSPV9EB
URJDAKB5B73KUcUS1N3RUVDQZSOBHO5RG949M1T33EDDA2BPBSXOQD9WYTDRPJ0Q
H7HOGU3R552J_YFPWA4G962RNKSOSJFHVIOUC74NHAY6TX73RWN1XGKYLZZTDTGF
UQP23WP5N0Nt9LS1O7IS2MZ057GIV9QJ7W7A63Y43O2S7EGMI6FGRICK7IIHP5MH
300DVT40G8oRZCAZAGKPF2P599J0TG1GGVD6PL454ALWBIZ0NOP8VSP25WAYHCH8
IMSH1VZ2PlSO1YH5506642503KKXIJYDAQFKX15G761PURGT7PFMWGLSZ1C71F4J
88BXKC18pV0ATM9PVVU6L489MOQLASEY2T7C3DPWHYTJT84WXGMSD58PO7XGBX73
1RVXI0P_EPUMI0C11CIIKPV2RBIFRX2GL4TSG2ENNXZ729YJ9RTCHSTR3W37PVDF
F091SFeWQ7TRP76NSZO50KHD6251GRZD2R1OH85BAYAVLF773Y18GI8YT9UVX4CV
34EK1hI5P9O0U6JUU6HQI6Q1C87WVYG77ZM1MJYPK7K7CSQ4YDIUXD55FE0U616K
BU2VtRIRSC4U05G5040FYY4O9K9DIIYSI52L2PVARFD1PMSPXYI7W42UODVJR5TL
Y1V{PPES44LLKZMRYDU0YSOYCEIFGZ0TVDEZU5ASK03LM6XP440I6BMPQZ0TI9QF
RMGZOCNZJY2N8A7CB356J1V47EHII4HIYYP3PNOB1B10USHRSQIA77BIPKDZ5VOA
5GQ6I2T9ZGLMNZMY6LGNGZU1PDQHL2LX28EKU233AOHWXHP2KETZ0ERH2I3QYO1J
EOK6YAVSR5G4O5FCWK3FMA5457MEQQUVZFPFFLV6Y9PL6RYTL4MZ70WFNGR8GYZ6
```

Ved å starte nederst til venstre og lese oppover mot høyre langs "diagonalen" er det mulig å lese ut et egg. Dette kan også scriptes.

```python
lines = open("informasjon.txt").read().splitlines()
print(''.join(lines[len(lines)-1-i][i] for i in range(len(lines))))
```

Og resultatet er `EGG{the_plot_chickens}`.
