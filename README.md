# zsum

zsum is a command-line tool that calculates the checksum of a file, and optionally compares it to an expected checksum.

## Usage

```
Usage: zsum [options] [checksum] file

If checksum is provided, check if the file's hash matches the given checksum.
Otherwise, print the file's hash to stdout.

file is either a file path or the file's contents piped from stdin.

Supported hashing algorithms:
  blake2b_128
  blake2b_160
  blake2b_256
  blake2b_384
  blake2b_512
  blake2s_128
  blake2s_160
  blake2s_224
  blake2s_256
  blake3
  md5
  sha1
  sha224
  sha256
  sha384
  sha512
  sha3_224
  sha3_256
  sha3_384
  sha3_512

Options:
  -a, --algo   The hashing algorithm to use (default: sha256).
  -h, --help   Print this help message and exit.
```

## Why?

I don't use a package manager on windows, so it's not uncommon that I have to install software manually.
Typically, I don't bother checking the checksum because it's too much of a hassle to type `Get-Filehash ...`
and visually verify that everything matches. And while I have some level of trust in the sources I download from,
this is still a security hole, so I decided to write `zsum` to hopefully make checking checksums a habit.
