# SHA-1 Password Cracking Project

This project demonstrates how weak and predictable passwords can be cracked when stored using the outdated **SHA-1 hashing algorithm**.  
The cracking process was implemented **entirely in Python**, without using external tools like Hashcat or John the Ripper — highlighting both the vulnerability of SHA-1 and the importance of strong password design.

---

## 📌 Project Purpose

The goal of this project was to recover plaintext passwords from a provided list of SHA-1 hashes by modeling real-world password habits such as:

- Simple numeric passwords
- Dictionary words
- Words combined with digits (e.g., `marching2023`)
- Common transformations (e.g., capitalization, repetition)
- Multi-word combinations
- Basic **leetspeak** substitutions

This demonstrates how attackers leverage predictable human behavior to crack passwords efficiently.

---

## 🧠 How It Works

The password cracker runs through multiple strategy phases in increasing complexity:

| Step | Strategy |
|-----|----------|
| 1 | Pure numeric sequences |
| 2 | Common date patterns |
| 3 | Direct dictionary matching |
| 4 | Word transformations (capitalize, reverse, repeat, etc.) |
| 5 | Word + digit combinations |
| 6 | Leetspeak substitutions |
| 7 | Two-word combinations |

The script uses **multiprocessing** to speed up execution across CPU cores.

---

## 📁 Repository Contents

| File | Description |
|------|-------------|
| `project.py` | Main password-cracking script (strategies + multiprocessing logic) :contentReference[oaicite:0]{index=0} |
| `Crypto Project Report.pdf` | Full written analysis, methodology, results & insights :contentReference[oaicite:1]{index=1} |
| `cracked_passwords.txt` | Output list of recovered plaintext passwords mapped to user IDs :contentReference[oaicite:2]{index=2} |

---

## ✅ Results

- **Total SHA-1 hashes provided:** 20  
- **Total passwords cracked:** 20  
- **Success rate:** **100%**
- **Time to crack:** ~12–16 hours (depending on CPU performance)

This confirms that:
> **SHA-1 is insecure and should not be used for password storage.**

---

## 🛡 Security Recommendations

| Recommendation | Why |
|---------------|-----|
| Replace SHA-1 with modern hashing algorithms like **Argon2id**, **bcrypt**, or **scrypt** | They are slow-by-design and resist brute-force attacks |
| Enforce password entropy rules | Predictable passwords = easy targets |
| Encourage password managers | Reduces reuse and predictable patterning |
| Add salting + rate limiting | Prevents offline cracking and mass-guessing attempts |

---

## 🚀 How to Run the Script

Ensure the following files are in the same folder:
passwords.txt
dictionary.txt
project.py

## 👨‍💻 Author

**Sai Pranay Kowshik Chowdary**  
*M.S. Cybersecurity — University of South Florida*

**GitHub:**  
https://github.com/koushikchowdary6  

**LinkedIn:**  
https://www.linkedin.com/in/koushik-chowdary/

