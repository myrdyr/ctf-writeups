# Where is the flag???

The task contained a disk image with a COW filesystem. Inspecting each revision, there were nothing interesting at first glance. Lots of poetry and pictures of flags.

But this string was a bit suspicious...

`GRSSANBTEA2TGIBUGMQDGMJAGM4CAN3CEAZTIIBTGQQDGNBAGM2CANLGEA3DGIBTGAQDGMBAGMYCANTDEA2WMIBXHEQDGMBAGMYCAMZQEAZDCIBSGEQDEMJAGVTCANJTEAZTGIBWGMQDOMRAGMZSANZUEA2WMIBWGYQDMYZAGM2CANRXEA2WMIBWGYQDOMRAGMYCANTEEA2WMIBXGQQDMOBAGM2CANLGEA3DEIBTGQQDMZJAGZRCAN3E`

..and it turned out it was simply base32-encoded for

`4e 43 53 43 31 38 7b 34 34 34 34 5f 63 30 30 30 6c 5f 79 30 30 30 21 21 21 5f 53 33 63 72 33 74 5f 66 6c 34 67 5f 66 72 30 6d 5f 74 68 34 5f 62 34 6e 6b 7d'

which is hex for

`NCSC18{4444_c000l_y000!!!_S3cr3t_fl4g_fr0m_th4_b4nk}`