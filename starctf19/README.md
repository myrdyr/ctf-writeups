# <a name="otaku"></a>Otaku

We are given two files: `Anime_intro.doc` and `flag.zip`. The zip file contains two encrypted files: `flag.png` and `last words.txt`. On the challenge page, there is a hint stating that `The txt is GBK encoding.`.

Testing out a few common passwords, plus words from the document, doesn't seem to yield anything worthwhile. But when we look closer in the document, there is some extra text hidden inside one of the striked-out sections. That text turns out to be the "real" last words of some anime character, and the length (431 bytes) almost matches the length of `last words.txt` (432 bytes). However, if we store the text as GBK encoding (as per the hint), one of the "\`" characters now take up two bytes! If these files are equal, we can mount a known-plaintext attack on the zip archive itself, using Biham and Kocher's attack method. Calculating the CRC of our known plaintext, we see that it matches the CRC of `last words.txt`. Now the important part is to compress our known plain-text without a password, and **use the same compression method as the original archive**. Fortunately, they used WinRar for this, and it has embedded the string `winrar 5.70 beta 2` near the end of the file. I couldn't find the exact beta version for download, but I found 5.70, which turned out to be good enough. I zipped down the text snippet I found, saved in GBK encoding, using default settings.

So now we have have two zip files: One encrypted with two files in it, and one unencrypted with an exact replica of the txt file from the first archive inside it. Now we can run [bkcrack](https://github.com/kimci86/bkcrack) against it like so: `./bkcrack -C flag.zip -c "last words.txt" -P knownplain.zip -p "last words.txt -e"` which tells bkcrack to target the file `last words.txt` inside `flag.zip` and a file with the same name in `knownplain.zip` for its attack. The last flag also asks it to continue searching for keys exhaustively. After running for a while, we get two key candidates. Unfortunately, I wasn't able to actually decrypt the zip file with any of them using bkcrack, but I could re-use the key `106d3a93 6c0cc013 338e8d6f` with [pkcrack](https://github.com/keyunluo/pkcrack) to recover `flag.png`. But of course, the image doesn't straight out tell you the flag. Time for steganography! Fortunately, it's a PNG, and `zsteg` is able to recover the flag immediately: `*ctf{vI0l3t_Ev3rg@RdeN}`


# <a name="sokoban"></a>Sokoban

We are given a server to connect to, with the information that we need to beat 25 levels in less than 60 seconds. Upon connection, we are greeted with the following message:
```
Welcome to this Sokoban game!(8:wall,4:human,2:box,1:destination)
tips:more than one box
8888888888
8000000008
8042010008
8000000008
8888888888
tell me how to move boxes to their destinations in least steps.(By wasd operations):
```

The first level is very easy, and completely static, and basically just serves as a sanity check for your event loop. The rest of the challenges are seemingly randomly generated and require quite a lot of moves. In addition to that, they are asking us for the **move optimal** solution to each level, i.e. the solution with the minimal amount of move operations. My solution can be found in `sokoban.cpp` and `sokoban.py`, but the main methodology was just to find a solver online that used BFS (Breadth-First Search), as their solutions will always be move optimal. There were quite a lot of fancy A\* solutions with meet-in-the-middle optimizations and such, but they rarely stumbled upon the move optimal solution. I then tweaked this solver to read input from a file, and made the Python script translate the board, write it to a file, call the solver, and then translate the resulting moves to `wasd`. (At this point I had multiple tools that understood a more common symbol format, so it made sense to keep that translation instead of hard-coding it in cpp.)

The script isn't extremely fast, but unless you stumble over a lot of solutions that have a really long solution, it should finish in time: `*ctf{Oh!666_What_a_powerful_algorithm!$_$}`