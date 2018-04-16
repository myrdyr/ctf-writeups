# Web 100 Factor as a service

A similar task was given last year, but this one was very refactored. Once entering the site, you were presented with only some static HTML and no obvious files were available, like robots.txt, sitemaps or repositories. 

It had two parts to it:

1. You received a cookie when entering the site, which looked like `"gqVhZG1pbsKsc2VjdXJpdHlfbHZsAQ=="`. Long story short, it was a serialized `msgpack` object, base64-encoded. Parsing it with the appropriate module revealed that it actually looked like this: `{b'admin': False, b'security_lvl': 1}`. We couldn't find that security level actually did anything, but setting admin to True and serializing/encoding it, then setting it as a cookie, gave us more options when visiting the site.

2. Now we could enter any number and make the server return the prime factors to us. We immediately suspected it to be a shell injection to `factor` like last year, but we were proved wrong. Also, whenever something went bad, the remote server would just return an error code and nothing of value. After experimenting a bit, we figured out that we could do basic math, and finally that it was running in a python environment.

We opted to exfiltrate the flag as numbers. After reading that `len(open("flag.txt").read()` was 48, we run script.py to get the flag out, byte per byte.