# Secure note service

Comments in the source mentioned committing "note":
- /note is available, which crashes saying it expects a valid id. When given an id, it complains about a missing signature.
- A .git folder is available. Copying it, and reseting to HEAD, we get the source. Looking in the logs, there is a commit removing a Django secret.
- We use a script to sign the message id that we want to request (1), which gives returns `CSWt_PVlDPLKgmfBL9n50q7vyUQ`.

`curl -v -Fsignature="1:CSWt_PVlDPLKgmfBL9n50q7vyUQ" http://ncsc.ccis.no:4343/note/1
{"id":1,"created":"2018-04-09T20:32:15.993269Z","description":"NCSC18{G00d_y0u_d1dnt_g1t_up!}"}%`