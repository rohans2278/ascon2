# ASCON — C++ Implementation

(c++ migration from https://github.com/rohans2278/ascon)

A lightweight Python implementation of the ASCON authenticated-encryption algorithm, based on the official ASCON specification:  
https://ascon.isec.tugraz.at/files/ascon.pdf

---

## 📌 Overview

ASCON is a lightweight authenticated encryption algorithm designed for constrained devices such as IoT hardware and embedded systems. It was selected by NIST during the Lightweight Cryptography standardization process for its strong security guarantees and efficient performance.

This Python implementation closely follows the ASCON specification’s AEAD mode. It provides:

- **Encryption** (produces ciphertext + authentication tag)  
- **Decryption** (verifies tag + returns plaintext)  
- **Associated data support** (optional)