# zsum

zsum is a command-line tool that calculates the checksum of a file, and optionally compares it to an expected checksum.

## Usage

```
Usage: zsum [options] PATH

Print the hash of PATH to stdout. If PATH is '-', read from stdin.

If PATH is a file, hash the contents of the file.
If PATH is a directory, hash the file paths and their contents.
Empty directories and file metadata are ignored.

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
  -a, --algo       The hashing algorithm to use (default: sha256).
  -c, --checksum   The expected hash to check against. If given, no hash will be printed.
                   If the hashes match, exit with code 0. Otherwise, exit with code 1.
  -h, --help       Print this help message and exit.
  -l, --list       List all files in the directory and their hashes. If given, PATH must be a directory.
  -v, --verbose    Print stats to stderr.
```

## Why?

I don't use a package manager on windows, so it's not uncommon that I have to install software manually.
Typically, I don't bother checking the checksum because it's too much of a hassle to type `Get-Filehash ...`
and visually verify that everything matches. And while I have some level of trust in the sources I download from,
this is still a security hole, so I decided to write `zsum` to hopefully make checking checksums a habit.
