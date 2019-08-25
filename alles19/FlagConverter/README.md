# Flagconverter

Challenge description:
```
On the campground of the CCCamp, someone is trying to troll us by encrypting our flags. Sadly, we only got the memory dump of the PC which encrypted our flags.
```

This challenge includes a single memory dump, with 3 challenges inside. The dump is from a Windows 7 64-bit machine, and inside it there's supposedly someone that has encrypted some flags. One was very recently encrypted, and another was encrypted a long time ago. Let's get to it.

# Part 1

This part is fairly simple. The flag exists somewhere in the memory as-is, with no obfuscation. Simply `fgrep -a "ALLES{" flagconverter.dmp` to get the flag.

`ALLES{f0r3n51k_15_50m3t1m35_t00_345y}`

# Part 2

We're going to use [Volatility](https://github.com/volatilityfoundation/volatility/) to analyze the memory dump. First, we start off with an `imageinfo` to identify which profile to use. Here, Volatility runs a few useful scans to determine the best profile fit. We end up with `Win7SP1x64`, which will be used for the rest of this write-up.

```
$ vol.py -f flagconverter.dmp imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (flagconverter.dmp)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800027ff120L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002801000L
                KPCR for CPU 1 : 0xfffff880009eb000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-08-21 05:55:09 UTC+0000
     Image local date and time : 2019-08-21 07:55:09 +0200
```

Next up, we'll run `pslist` and `filescan` to see what we have available. The outputs of these are enormous, but there's a few interesting files and applications being run. Some of these are located on the desktop for the ALLES user:

```
0xfffffa800246e530 converter.exe          2308   2280     11      183      1      0 2019-08-21 05:52:25 UTC+0000
0xfffffa800246fb00 converter.exe          2316   2280     10      152      1      0 2019-08-21 05:52:25 UTC+0000
...
0x000000003e66a6a0     15      0 R--r-- \Device\HarddiskVolume2\Users\ALLES\Desktop\1\converter.exe
0x000000003eb79430      1      1 R--r-d \Device\HarddiskVolume2\Users\ALLES\Desktop\3\Crypto.dll
```

Dumping these wasn't easy to do uncorrupted with Volatility, but we managed to do so after some combination of memory areas. `converter.exe` is a .NET application, and firing up `dnspy` reveals that it's just a thin form application that interacts with `Crypto.dll`. There's a text field, and a button to press for encrypting. The `Click_Button` function looks like this:

```
private void Click_Button(object sender, EventArgs e)
{
    Crypto crypto = new Crypto();
    crypto.function03();
    this.string_0 = Convert.ToBase64String(crypto.function02(this.text.Text));
    crypto.Dispose();
    GC.Collect();
    GC.WaitForPendingFinalizers();
    this.ms.Read(Encoding.ASCII.GetBytes(this.string_0), 0, Encoding.ASCII.GetBytes(this.string_0).Length);
    this.text.Text = this.string_0;
}
```

Here it initializes the Crypto class, calls some `function03`, followed by `function02` on the text in the input field, and finally base64-encodes the result. The application also aggressively interacts with the garbage collector, to make sure the flag doesn't stay in memory after encrypting. Looking at `Crypto.dll` in `dnspy`, we easily find these functions:

```
public void function03()
{
    byte[] array = new byte[28];
    WindowsIdentity.GetCurrent().User.GetBinaryForm(array, 0);
    this.byte_1 = new byte[16];
    Array.Copy(array, 0, this.byte_1, 0, 16);
    this.byte_0 = new byte[32];
    Array.Copy(array, array.Length - 16, this.byte_0, 0, 16);
    Array.Copy(array, array.Length - 16, this.byte_0, 16, 16);
}

public byte[] function02(string string_0)
{
    SymmetricAlgorithm symmetricAlgorithm = this.function01();
    MemoryStream memoryStream = new MemoryStream();
    CryptoStream cryptoStream = new CryptoStream(memoryStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write);
    byte[] bytes = new UnicodeEncoding().GetBytes(string_0.PadRight(string_0.Length % 8, '\0'));
    cryptoStream.Write(bytes, 0, bytes.Length);
    cryptoStream.FlushFinalBlock();
    memoryStream.Position = 0L;
    byte[] result = memoryStream.ToArray();
    string_0 = null;
    cryptoStream.Close();
    memoryStream.Close();
    GC.Collect();
    GC.WaitForPendingFinalizers();
    return result;
}
```

The gist of it, is that `function03` fetches the SID of the current user, in its binary form, which is a [big mess of big and little endian hexadecimal chunks](https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253). It is only 28 bytes long, but it copies the first 16 bytes into `byte_1` and the last 16 bytes into `byte_0` two times. `function03` then uses AES in CBC mode, with `byte_1` as the IV and `byte_0` as the key for encryption. Aggressive garbage collection is also done here. An equivalent decryption function in Python looks something like this:

```python
from Crypto.Cipher import AES

def decrypt(SID, ciphertext):
    IV = SID[:16]
    KEY = SID[len(SID)-16:]*2
    return AES.new(KEY, AES.MODE_CBC, IV).decrypt(ciphertext)
```

Now that this is out of the way, we just need to hunt for base64-encoded data somewhere. We actually found part 3 before part 2, but part 2 can be found within the memory dump of the `converter.exe` process using `strings` or similar tools. It is `ZuwJUgfmKzIMbo4F8agPy1MPLq+r7cAlDLowY+RT2wgp1uifc2TXeNH4bvbb2VqfK6r77SPHFrrMYR+GMGv8JGS87Tiybyi4LNNHQWnTR8LlGlSeHWWA9pydAXuJjSk8FzUFbqHOKqHc+bCtJ/4K2Q==`, and using the decrypt function from above together with the SID `0105000000000005150000009a54b0afcd26c4824b70f4b0e8030000` (decoded from hex) and the base64-decoded bytestream of our flag yields `ALLES{50m3_f0r3n51k_50m3_r3v3r51ng_4nd_50m3_c2ypt0_fun}`. We actually found this string by looking through the screen buffer in the image, where we stumbled upon a somewhat legible image of the screen state, where the encrypted flag was located. We then grepped for the readable parts to find part 2. The SID can easily be found with the `getsids` plugin, but it is also visible inside the filescan results (and many other places).

# Part 3

Part 3 is the exact same thing as part 2, but this time around you should've noticed a weird file in the filescan. It is also present if you run the screenshot plugin of Volatiliy, where it shows a large part of the base64-encoded and encrypted flag. We first noticed this though:

```
0x000000003e6645a0     16      0 R--r-d \Device\HarddiskVolume2\Program Files\D9f\gCFhd\yxEUQSFyoHU1ybvQ0S9TOOwUWFCR+HWh+YicMXXJ2hzO39bjKEbONClpsoTzUtfuC86APEJGe46byt7fmJGBEkmrtktbMIZ5Mk4LnGFkyNVkAwEKm\O7dnFs7JKPrXrI9Co8Z4ULFf1UzT1cK5wFiIONE\0t33K+0.bat
```

Simply running the same function as for part 2, with the same SID, gives the third flag `ALLES{0n3_f0r3n51k_tr345ur3_15_ly1ng_w1th1n_th3_5h1mc4ch3}` You only have to flip the backslashes forward before decoding.