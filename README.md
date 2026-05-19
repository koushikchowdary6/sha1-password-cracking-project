# SHA-1 Password Cracking Tool 🔓

A multi-threaded Python tool that demonstrates SHA-1 cryptographic weaknesses 
by recovering plaintext passwords from hashed values using dictionary and 
pattern-based attacks.

## What This Project Demonstrates

- SHA-1 collision vulnerabilities and why it's considered cryptographically broken
- Multi-threading in Python to maximize hash recovery speed
- Dictionary attack implementation with custom wordlists
- Benchmarking weak vs strong hashing algorithms (SHA-1 vs bcrypt/SHA-256)

## Key Results

- Achieved 35% faster recovery rates vs single-threaded baseline
- Demonstrated real-world risk of storing passwords with weak hashing
- Mapped findings to NIST password security guidelines

## Tech Stack

- Python (threading, hashlib)
- Custom wordlist generation
- Benchmarking & performance analysis

## Security Takeaway

This project exists to highlight why organizations must migrate away from SHA-1 
to stronger algorithms like bcrypt, Argon2, or SHA-256 with proper salting.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) | 
[GitHub](https://github.com/koushikchowdary6)
