# Solution
1. Go to "Lorem Ipsum" on Wikipedia.
2. Copy the text from this SVG https://upload.wikimedia.org/wikipedia/commons/8/86/Lorem_ipsum_design.svg
3. Cut away any parts that are not in the corrupted text file.
4. Make sure the new file and the corrupted file are lined up 100%, including line endings. Lengths should be the same.
5. For each character in both texts, if they differ, XOR them together and save the result.
6. The flag is the concatenation of each XORed byte.