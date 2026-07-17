# SHA-1 Password Cracking Tool 🔓

A multi-process Python tool that demonstrates why SHA-1 is unsuitable for
password storage: unsalted SHA-1 hashes fall quickly to dictionary and
pattern-based attacks. Given a file of `user_id <sha1_hash>` pairs, it
recovers the plaintext passwords and reports a success rate.

## How it works

The cracker runs seven strategies in order, stopping early as hashes are
recovered:

1. **Pure digits** — all numeric passwords up to `MAX_DIGIT_LEN`
2. **Common dates** — `YYYYMMDD`, `DDMMYYYY`, `MMDDYYYY` across a range of years
3. **Dictionary words** — direct wordlist lookup
4. **Word transformations** — capitalization, upper-case, reversal, repetition
5. **Word + digit combinations** — appended/prepended numbers and separators (parallelized across CPU cores)
6. **Leetspeak** — `a→4/@`, `e→3`, `i→1/!`, `o→0`, `s→5/$`, etc.
7. **Word-pair combinations** — two words joined by common separators (parallelized)

Parallel strategies use Python's `multiprocessing.Pool`, sized to the
machine's CPU count.

## Run it

```bash
python3 project.py
```

It reads `passwords.txt` (the target hashes) and `dictionary.txt` (the
wordlist), both included as a small demo set, and writes recovered
passwords to `cracked_passwords.txt`.

### Input format

`passwords.txt` — one target per line:

```
1 7c4a8d09ca3762af61e59520943dc26494f8941b
2 9bcea4483a009e15aa649981c183c5819dd9e185
```

`dictionary.txt` — one candidate word per line.

## Demo result

Against the included 10-entry demo set (one password per strategy), the tool
recovers **10/10 in about 2 seconds** on a typical laptop:

```
--- Cracking Summary ---
Total hashes loaded: 10
Total passwords cracked: 10
Hashes remaining: 0
```

## Tuning

Two constants at the top of `project.py` trade coverage for runtime:

| Constant | Default | Effect |
|---|---|---|
| `MAX_DIGIT_LEN` | 6 | Longest pure-digit password to brute-force (each +1 is ~10× slower) |
| `MAX_APPEND_DIGITS` | 3000 | Numeric range tried in word+digit combinations |

Raise them for harder targets, but note that `MAX_DIGIT_LEN = 8` alone means
10^8 hashes — minutes, not seconds.

## Security takeaway

This is exactly why modern systems don't store passwords with a fast, unsalted
hash. Use a slow, salted, memory-hard algorithm — **Argon2id** (or bcrypt/scrypt)
— so that each guess is expensive and precomputation/rainbow tables don't help.
SHA-1 additionally has known collision weaknesses (SHAttered, 2017) and is
deprecated for security use.

> For educational use on hashes you are authorized to test. Don't run this
> against data you don't own.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)
