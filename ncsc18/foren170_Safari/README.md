# Safari

This one was a 3-part challenge. The initial capture filed contained 3 sequences of interest:
1. Tons of DNS requests.
2. A few ICMP requests
3. Some SMTP traffic.

## DNS requests

- Stripping out all the DNS requests using tshark (see script) and cleaning out the last part of the hostname reveals a long base64-encoded string. Decoding it resulted in a new file.
- Running binwalk on it revealed an ELF file, a separator string, and a ZPAQ archive. The ELF turned out to be a red herring.
- The ZPAQ archive contained a new file, cappy.pcapng. In this file, someone uses the SAFT protocol to send someone a file, but some parameters have been erased and the file is corrupted.
- One of the lines read "BINARY COMPRESSED=..." and by reading the docs, we see there are two compression standards: GZIP and BZIP2.
- The file turns out to be very clearly a BZIP2-file, but its header is broken. We fix this by replacing BX in the start with BZ, and moving the extra Y to the end of the "PI-hex" part of the header.
- Out comes a new file, this time a broken PNG file. The header reads "GNP" and the IDAT, IHDR, etc. text fields are corrupted. Fixing them revealse the first part of the flag (Part_1.png).

## ICMP requests

- Looking at these, the checksums are reported as being wrong. Studying the ASCII version of the checksums, we see it is morse code with some garbage. We decoded it to be `15_W45_D4_53C0ND_0H`.

## SMTP traffic

- Someone sends an email with an MP3 file. When extracting it, we can see a flag written in the spectrogram of the audio in it (Part_3.png).

Final flag was

`NCSC18{7H15_15_7H3_F1R57_P4R7_4ND_7H15_W45_D4_53C0ND_0H_w417_15_7h15_b64_n07_r34lly}`