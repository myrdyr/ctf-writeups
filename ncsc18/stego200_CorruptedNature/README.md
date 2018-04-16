# Corrupted Nature

The image had a text in the lower-right corner, hinting that we should increase the dimensions. Changing them from 2016x1512 to 2016x1640 using tweakpng, a white field with the text `AES128 password: Media White Point` was revealed. Tweakpng also reported that the CRC of the IHDR was wrong.

A hint was released, pointing to the tool OpenStego. We had already tried this, but only on the pristine image. After testing it on the image after changing dimensions and fixing the CRC, using the password `0.94955 1 1.08902` (the media white point, as reported by exiftool), the file `Flag04.txt` popped out with this flag repeated:

`NCSC2018{Secret:k\(:)/m.i.}`

The make it accept the flag, we changed the input to start with `NCSC18` instead.