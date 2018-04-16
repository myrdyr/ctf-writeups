# Painvin

Ciphertext is `AAGDADAAAVVVDVADDVAAFFFAADDVDAADAAADFFAFVDVAADADAFAGFFADAAADVFFAGDFVDAAAFAGDAADVVDDAFVDVFAFVFDDDVAVDDVFAGDFDADFAFADAFAFAGAAADDVGGADAFAVAAAAAAVAFADAAGDDADAAFAADFADDDDFGVVVGAFDVVDGVXVGFDFDAVGXGGDDVFAVVFFDDFGVGFDAVXFDDFDDDAFAAAXAFVGADAAAVADVGXFVFVGDVVADDAAVDADDGAADAADGDFFFGGGAAVDDGVDGDFFDAAADADDDGAAAAFFGVAAGFGFDFAFDVAVGADFDVDDGADGVVDXVVVAVDDFVFAFDDVADFDGXFVAFVGXFVVADDXVFDDGXGFGVADFDAFAVVXADDADXFDVVGGVADFFVXFVDFVDVXVDVDDFXDAXDVDVGAVVADAVADXAVDVAVAVGVVADVGGXDDDFVVDGADDDAVFVDXVGAXDXVDFXDDAVAAD`

Very recognizable as ADFGVX cipher (not to be mistaken for ADFGX). We didn't understand that the key was supposed to be "CYBERS", despite the hint, but we basically brute-forced it knowing this:
- ADFGVX is basically substitution cipher + column transposition.
- Each letter [A-Z0-9] is mapped to exactly one bigram (AA, AD, AF, etc.) before the bigrams are "mixed" based on the key.
- This opens up to one attack, where if you suspect that the message contains no numbers, the amount of unique bigrams will be significantly less when you properly reverse the column transposition.
- We found that for key length 6, the amount of unique bigrams sometimes fell from 36 to only 26.
- Knowing this, we could look through all transpositions, "normalizing" them, i.e. transforming each unique bigram to a specific letter. We could solve this resulting string as a simple substitution cipher. But it turned out to be difficult due to the letters used in the plaintext.

- A hint was added, stating that AAFIVEZEROSIXBRAVOB was part of the plaintext. With this, we found that the only matching inverse column transposition step was (5, 1, 2, 0, 4, 3). This gave the ciphertext:

`ABCDEFGHDFIJKDKFIDGLDDMFGENOODPFJKFJJJQNCDRDEBKNFIEJCBIEJCBSTPNDGGSTPNDGGLHNKUDVQNCDGJMWBXTDIDAVJMUDDXTDIDASTPNDGGHBGDPKDCDMIEJCBIEJCBLHNKUDVBKAJEHBGDPBMDQBFGEBGGLBTMNQBEYBMDBMDYNUDRTPTZDPGJDNWHGDNWHGPNYJKNFBMDKDCDMHBGDPDNWHGBKAJEXTDIDAKNFQNCDJJJ`

and we could see that JJQNCDRDEBKNFIEJCBI=AAFIVEZEROSIXBRAVOB, thanks to the hint, by looking for sequences in the string with repeating letters (two AAs then another A 14 steps to the right etc.)

The resulting plaintext was 

`COVER X THE X BASES X BETWEEN X TRIPPEL X AS X AAA FIVE ZERO SIX BRAVO BRAVO JULIETT JULIETT WHISKEY FIVE TANGO QUEBEC YANKEE QUEBEC JULIETT HOTEL SEVEN BRAVO BRAVO WHISKEY OSCAR HOTEL ONE FOXTROT TWO UNIFORM ONE ONE MIKE ZULU DELTA EIGHT EIGHT LIMA SIX ONE SEVEN HOTEL EIGHT OSCAR QUEBEC SIX FIVE AAA`

Which translates to "506BBJJW5TQYQJH7BBWOH1F2U11MZD88L617H8OQ65". This was written in base36, and we could find the flag with a short snippet:

```python
>>> hex(int("506BBJJW5TQYQJH7BBWOH1F2U11MZD88L617H8OQ65",36))[2:-1].decode('hex')
'NCSC18{Painvin274572336456}'
```
