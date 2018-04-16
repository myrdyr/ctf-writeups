# Turtles all the way down

We are given an image, `TurtleB.png`. Testing out various steganography tools on it, we find that using `steghide` with no password produces `TurtleC.jpg`. binwalk revealse that `TurtleC.jpg` is actually a JPEG + PNG mashed together, revealing a QR code. The QR code reads:

`Hey, that's not a turtle! That's a tortoise. You promised us turtles. Quit messing with us!
OK. Here's a secret I'll share with you; I never really liked NINJATURTLES`

We also noticed some noise in the top corner of the QR code, but had no luck in decoding it. We suspected it to be some LSB stego, but no tools or manual efforts gave anything worthwhile. (And we didn't know what to look for).

Then a hint was then revealed, pointing to the stego tool "stepic". Installing this, and using it on the QR code with password "NINJATURTLES" produced a PKZIP-file. Inside, another QR code called `TurtleE.png`. Scanning it revealed the fake flag `NSCS18{NinjaTurtlesRulez114458894158}`. But this image also had some noise in the upper-left corner. Running stepic again revealed the actual flag:

`NCSC18{GreatA'Tuin270645515661}`