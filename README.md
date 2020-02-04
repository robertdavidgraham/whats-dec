# whats-dec - WhatsApp end-to-end media decryptor

This program decrypts WhatsApp end-to-end encrypted media files (like videos and pictures).
You need to first extract the key from either end of the communication, such as from
a phone backup. This is decribed below for the iPhone. This program will then decrypt
the media file.

The WhatsApp encryption process adds up to 26 bytes to the end of media files for
verification and padding. Some people have suspected these extra bytes might contain
malware. Thus, this program clearly extracts those bytes and shows them, so that
you can be certain they contain nothing malicious.

This program was written in response to the news story from January 2020 that claimed
Saudi Arabia hacked Jeff Bezos's iPhone. The report was based on the suspicion that
a video sent from Crown Prince MBS contained malware. The investigators did not know how
to decrypt to the video, so assumed it contained malware, especially due to the extra
bytes in the encrypted file. This project allows that file to be decrypted, conclusively
either pointing the finger at MBS, or exonerating him.

## Building

This program is written entirely in the C programing language with no dependencies.
It'll compile on Windows, Linux, macOS, and many other places.
It relies on no other dependency other than the standard C library
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

 ## Example usage

 A friend used WhatsApp to send a video to my iPhone. I backed up the phone
 to my computer, and using the steps above, extracted both the URL of the
 encrypted video and the key.

 The URL was https://mmg-fna.whatsapp.net/d/f/AsnGB7gNh6Yw52MScbJyTRMo3NCmzMpesUIYyFmEZ0lR.enc.
 The key was `TKgNZsaEAvtTzNEgfDqd5UAdmnBNUcJtN7mxMKunAPw=`.

 I used the program `curl` to download the encrypted video. I then used this program
 to decrypt the file.

    $ curl https://mmg-fna.whatsapp.net/d/f/AsnGB7gNh6Yw52MScbJyTRMo3NCmzMpesUIYyFmEZ0lR.enc -o rob.enc
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
    100 21.1M  100 21.1M    0     0  10.2M      0  0:00:02  0:00:02 --:--:-- 10.2M
    $ ./whats-dec --key TKgNZsaEAvtTzNEgfDqd5UAdmnBNUcJtN7mxMKunAPw= --in rob.enc --out rob.mp4
    [+] ciphertext = rob.enc
    [+] plaintext  = rob.mp4
    [+] mediakey = 4ca80d66c68402fb53ccd1207c3a9de5 401d9a704d51c26d37b9b130aba700fc
    [+] mediakey.iv = 4367627b7897b3e4efaef9a38cb49611
    [+] mediakey.aeskey = 234b96b5349e39f221481eb91b25ef20 a2a93b68b37eb5785b51aadda36150db
    [+] mediakey.mackey = a329f783e12eb633fce420a03d79cc83 4804f5f9931b53e150b92a3c04564ec7
    [+] block[0] = 000000206674797069736f6d00000200
    [+] block[n] = 38fc59f852020314216e
    [+]-padding = 060606060606
    [+]-mac = 03017057a92305495b1b
    [+] MAC = 03017057a92305495b1b07aca393fdff 030280957c08bd2f01e29bae67a7dbeb
    [+] matched! (verified not corrupted)

At the end of the file are additional `padding` and `mac` fields. This program clearly
decrypts those bytes so that you can be certain there is no malware inside them.

In this
example, the padding contains six bytes, all with the value of 0x06. There may be as
many as 16 bytes of padding, however many needed to fill out the final block in the
file. After the final block comes 10 bytes of of the "message authentication code"
that verifies the file hasn't been corrupted in transit, either accidentally or
intentionally. The calculated MAC will be 32-bits long, but only the first 10 are
included in the download. As we can see, the first 10 bytes match, so the file hasn't
been corrupted.
