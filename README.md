# whats-dec - WhatsApp end-to-end media decryptor

This is a program for decrypting and decoding WhatsApp end-to-end encrypted
media files (videos, photos, audio).

This is written in responsibe to the January 2020 story claiming Saudi Crown
Prince MBS hacked the iPhone of Amazon CEO Jeff Bezos. The report said it
could not decrypt the video sent by MBS to Bezos, and the phone acted
strangely after receiving the video. The implication is that the video
probably contained some sort of hack or virus.

However, such things can be easily decrypted. The term "end-to-end" means
nobody in the middle can decrypt it, including the service provider like
WhatsApp. However, those in posession of the "ends" can still decrypt it.
The necessary decrypt key is, in fact, located right next to the encrypted
filename within the WhatsApp database, so there's no reason why the
investigators couldn't decrypt the file. All they would need is a tool --
a tool like this one.

This program doesn't simply decrypt the file, but also spits out a lot of
diagnostic information about what it decoded in the file. One of the reasons
the investigators were suspicious of the encrypted file was because it was
slightly longer. In fact, WhatsApp encryption always adds between 11 and 26
bytes to the end of everything it encrypts, so this is not strange. This
program decodes exactly what those extra bytes are, so that this fact can
be verified.

This means that of suspecting MBS, we can either covict him beyond a shadow
of a doubt, or completely exonerate him. If the encrypted file contains 
an exploit or malware, we can know for certain. Likewise, if it doesn't,
we'll know that for certain as well.

The investigator Bezos hired used expensive tools marketed only to law
enforcement. However, everything the did can be done by you at home with
free tools. A section below describes how to do everything with your own
iPhone using free tools to decrypt Whatsapp videos from your own iPhone.

## Building

This program is written entirely in the C programing language with no dependencies.
It'll compile on Windows, Linux, macOS, and many other places.
It relies on no other dependency than the standard C library
(all the crypto routines are included).
Simply compile the files together, as in:

    $ cc *.c -o whats-enc

There is also a Makefile in the directory:

    $ make
    $ make test

You need a C compiler, such as Microsoft Visual C, `gcc`, or `clang`. On Debian
versions of Linux, this can be obtained by:

    $ sudo apt install build-essential

## Extracting end-to-end keys

End-to-end encryption means that nobody in the middle can decrypt messages or
content. The WhatsApp messaging app uses end-to-end encryption, meaning that
not even WhatsApp can decrypt either text messages or multi-media messages
containing video.

However, the devices on either end need to be able to decrypt these things.
That means the decryption keys are located somewhere on the device.
A forensics analysis of the device, or a backup of the device, should be
able to retrieve the decryption keys, and thus, decrypt any content.

For WhatsApp, these keys are stored in a file called `ChatStorage.sqlite`.

When you backup an iPhone, this file gets renamed to
`7c7fba66680ef796b916b067077cc246adacf01d`.

This file contains an SQL database. Inside that debase is a table called
`ZWAMEDIAITEM`. In that table are two columns of interest, `ZMEDIAULR` that
is the download URL for the encrypted media file, and `ZMEDIAKEY` needed to
decrypt it.

The `ZMEDIAKEY` contains more than just the key we need. It is a "blob"
containing binary data, which you can format in hex, as in the block
below:

    0a 20 31 67 ca 52 06 c6 e9 c3 5c 18 ea a0 5c 7e
    d3 d3 72 4f 46 65 3d d6 85 8e d5 62 d3 f7 6b 25
    58 90 12 20 70 21 23 08 1a 9f 8a c1 e2 80 29 b5
    f7 82 87 99 83 8d 66 32 d8 2b ad 58 78 9c c1 4f
    bb 80 90 bc 18 9f c4 e7 f1 05 20 01 

This blob is structured with `protobufs` and has four
fields. The first field contains the encryption key
that we'll use for the next step. The first byte
0a is the field tag, and the second byte 20 is the length
of the key, in this case 0x20 or 32 bytes. The next
32 bytes are the key, as in:

          31 67 ca 52 06 c6 e9 c3 5c 18 ea a0 5c 7e
    d3 d3 72 4f 46 65 3d d6 85 8e d5 62 d3 f7 6b 25
    58 90 

We use this key in the step below.

## Example usage

A friend used WhatsApp to send a video to my iPhone. I backed up the phone
to my computer, and using the steps above, extracted both the URL of the
encrypted video and the key.

The URL was https://mmg-fna.whatsapp.net/d/f/Aj_7Mge6zUvrFKT-B600W-hk36LiHU3zhh2W-UI0q4Ld.enc.

The key was `3167ca5206c6e9c35c18eaa05c7ed3d3724f46653dd6858ed562d3f76b255890`.

I used the program `curl` to download the encrypted video. I then used
this program to decrypt the file.

    $ curl https://mmg-fna.whatsapp.net/d/f/Aj_7Mge6zUvrFKT-B600W-hk36LiHU3zhh2W-UI0q4Ld.enc -o mbsvid.enc
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
    100 4331k  100 4331k    0     0  2506k      0  0:00:01  0:00:01 --:--:-- 2505k
    $ ./whats-dec --in mbsvid.enc --out mbsvid.mp4 --key 3167ca5206c6e9c35c18eaa05c7ed3d3724f46653dd6858ed562d3f76b255890 
    [+] ciphertext = mbsvid.enc
    [+] plaintext  = mbsvid.mp4
    [+] mediatype = video
    [+] mediakey = 3167ca5206c6e9c35c18eaa05c7ed3d3 724f46653dd6858ed562d3f76b255890 
    [a] info string = WhatsApp Video Keys
    [b] mediakey.iv = 8df703e1097a254e0c156eaa5715d3ab 
    [c] mediakey.aeskey = 2e294ad0892b1a985383c5d9c9e662fe a23ada93e19e973f02e4e2bd32930abf 
    [d] mediakey.mackey = 7f69685c88160ca3313a940c871afef6 bbab93278d9adba44e122bd695fbe0ee 
    [e] block[0] = 0000001c667479706d70343200000000 
    [f] block[n] = 5a5a5a5a5a5a5a5a5a5a5a5e
    [g]-padding = 04040404
    [h]-mac = fed41680725fba0dd4f1
    [i] MAC = fed41680725fba0dd4f1e8b3409bedef a35c13dadb5ecff72b79764df79af8d9 
    [j] matched! (verified unmodified)
    [k] SHA256(file).hex = 7ea5a6036f2e3a4a33ca18f1ac33c669 0cce86df371109af09a00574dda6509d 
    [l] SHA256(file).b64 = fqWmA28uOkozyhjxrDPGaQzOht83EQmvCaAFdN2mUJ0=
    [m] SHA256(enc).hex = 702123081a9f8ac1e28029b5f7828799 838d6632d82bad58789cc14fbb8090bc 
    [n] SHA256(enc).b64 = cCEjCBqfisHigCm194KHmYONZjLYK61YeJzBT7uAkLw=

The output marked with `[+]` just repeats the configuration given on the
command-line. The input encrypted file is that downloaded from `curl` stored in
`mbsvid.enc`. The decrypted file we are going to ouput will be written to
`mbsvid.mp4`.

Here is an explanation of the additional fields:

  * [a] info string
    This is a string needed for something called 'key expansion', derived
    from the output file type. If you think the file is one format, such as 
    a JPEG, but it's in fact another format, like an MP4, then it won't decrypt
    correctly (will appear corrupt). The correct format is stored in the database
    alongside the URL and mediakey, but it's likely you'll just already know
    the proper format before using this program.
  * [b] mediakey.iv
    Modern encryption needs not only a secret key but also an "initialization
    vector" or "nonce". This value is derived from the original mediakey that
    was passed into the program via the key expansion step.
  * [c] mediakey.aeskey
    The 256-bit mediakey is not the 256-bit AES key used to decrypt the file.
    Instead, the AES key is derived from the mediakey via key expansion.
  * [d] mediakey.mackey
    Modern encryption needs to not only encrypt the data but also verify
    that it hasn't been modified or corrupted, often using what's called
    a message authentication code. This also needs a key, which we also
    derived from the original mediakey.
  * [e] block[0]
    The first 16 decrypted bytes. If you see completely random stuff, then
    the encryption key may be bad and it's not working. Most file formats
    have a distinctive patterns, such as the numerous 00 bytes seen above.
  * [f] block[n]
    The last decrypted bytes from the last block, minus any padding.
    This is usually less than 16 bytes, as in the above example where it's
    only 12 bytes. It's also often non-random, as in the above example where
    it's mostly 5a bytes.
  * [g]-padding
    Since AES encrypts 16-byte blocks, the last block will be padded out to
    16-bytes. The last byte has a value from [1..16], indicating the number
    of bytes of padding. It appears that this byte is then repeated for all
    padding. We see above that there are 4 bytes of padding, so all the bytes
    have the value of 4.
  * [h]-mac
    After all the 16-byte blocks, the encrypted file now ends with 10 bytes
    of the "message authentication code", calculated by using a keyed
    hash over the entire contents. This code is 32-bytes long, but for 
    whatever reason, WhatsApp only appends the first 10-bytes. These
    10-bytes must match the first 10-bytes of the calculated value
    in [i] below.
  * [i] MAC
    The 32-byte message authentication code we calculated when decrypting
    the entire file. We only need the first 10-bytes to match the field
    above, but we have to calculate the entire 32-byte field, so it's
    shown here.
  * [j] verified/corrupted
    This field just reports whether the first 10 bytes of [i] and [j]
    matches, in case you couldn't see for yourself.
  * [k] SHA256(file).hex
    The keyed hash is used to tell if the file has been corrupted in
    transit. We also calculate other hashes (without a key). This
    hash is the SHA256 algorithm applied to the decrypted file,
    the same result if your run from the command-line `openssl sha256 mbsvid.mp4`.
    This is reported in hex. Whereas hashes like this are often used
    to detect corruption, they are also used as a file's identity.
    Two files with the same hash always have identical contents.
  * [l] SHA256(file).b6
    This is the same value as in [k], but encoded in BASE64. This is because
    WhatsApp often passes around this value encoded this way. In particular,
    in the same SQLite file that contains the mediaurl and mediakey, you'll
    find this same value stored under the ZCARDNAME field.
  * [m] SHA256(file).hex
    This is the hash of the encrypted file. In other words, this hashes
    the file after it was encrypted. It's the same as running the command
    `openssl sha256 mbsvid.enc`. This, too, is stored in the SQLdatabase.
    You'll find it as the second field in the protobuf holding the mediakey.
  * [n] SHA256(file).b64
    This is the same value as in [m], but encoded as BASE64 instead of HEX.

If you are worried about hackers hiding exploits or malware inside the
extra bytes of the encrypted version of the file, the place to look is
the "padding" and "mac" fields described above. As you can see in this
example, the bytes can't contain anything nefarious. The padding
contains all 04 bytes, and the 'mac' is predetermined by the calculation
and can't practically contain anything determined by the hacker.
