---
title: "RSA in Practice: From Number Theory to Secure Padding"
date: "2024-12-05"
excerpt: "A deep dive into RSA math, key generation, and why padding makes or breaks security."
featured: "/images/test1.jpg"
tags:
  - cryptography
  - rsa
  - security
  - math
---

## Why RSA still matters

RSA is old, but it is still everywhere: TLS handshakes, code signing, smart cards, and HSM-backed key stores. The math is simple, the engineering is not. This post focuses on the parts that break in the real world: padding, randomness, side channels, and key handling. Do not implement your own crypto[^1].

## Core math in one page

We work in modular arithmetic. For integers a, b, and modulus n:

- a == b (mod n) means n divides (a - b).
- a has a modular inverse mod n if gcd(a, n) = 1.

Pick two large primes p and q. Then:

- n = p q
- phi(n) = (p - 1)(q - 1)

Choose a public exponent e such that gcd(e, phi(n)) = 1. The private exponent d is the modular inverse of e:

$$
d \equiv e^{-1} \pmod{\phi(n)}
$$

The encryption and decryption rules are:

$$
c \equiv m^e \pmod{n}
$$

$$
m \equiv c^d \pmod{n}
$$

## A tiny worked example (not secure)

Let p = 61, q = 53, so n = 3233 and phi(n) = 3120. Choose e = 17, then d = 2753 because 17 * 2753 == 1 mod 3120.

If m = 65, then:

$$
c = 65^{17} \mod 3233 = 2790
$$

$$
m = 2790^{2753} \mod 3233 = 65
$$

The math works, but security does not. Small primes and textbook RSA are trivial to break.

## Key sizes and security levels

| RSA key size | Approx security bits | Typical use |
| --- | --- | --- |
| 2048 | ~112 | Legacy and mid-term |
| 3072 | ~128 | Common baseline |
| 4096 | ~152 | Long-lived keys |

Security is driven by the difficulty of factoring n, not by the size of e.

## Padding is not optional

Textbook RSA is deterministic. That means:

- Same message -> same ciphertext.
- Structure leaks to attackers.
- Low exponent tricks can recover messages.

Modern RSA uses padding. The most common safe choice is RSAES-OAEP. At a high level:

$$
\text{OAEP}(m) = (m \parallel 0^k) \oplus \text{MGF}(\text{seed})
$$

The important bit is randomness. Without it, RSA is not semantically secure. For signatures, use RSA-PSS, not raw RSA.

## Why hybrid encryption is standard

RSA is slow and only supports messages smaller than n. Real systems:

1. Generate a random symmetric key k.
2. Encrypt data with AES-GCM using k.
3. Encrypt k with RSA-OAEP.
4. Send (RSA(k), AES-GCM(ciphertext)).

This gives you speed and security, plus integrity from GCM.

## Attacks to keep in mind

### Low exponent and broadcast

If e is small and the same message is sent to many recipients with different moduli, a broadcast attack can recover the message without factoring n.

### Padding oracles

If a server reveals whether padding is valid, attackers can decrypt ciphertexts via a padding oracle attack. Error messages must be indistinguishable.

### Shared primes

If two keys share a prime (caused by weak RNG), then gcd(n1, n2) reveals the prime and factors both keys.

### Faulty CRT

CRT speeds up decryption but a single fault in one branch can leak the private key. Always verify the result or use blinding.

## Minimal Python demo (educational only)

```python
from math import gcd

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(e, phi):
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError("e not invertible")
    return x % phi

def rsa_keygen(p, q, e=65537):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("bad e")
    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt(m, n, e):
    return pow(m, e, n)

def rsa_decrypt(c, n, d):
    return pow(c, d, n)

# toy example
n, e, d = rsa_keygen(61, 53, 17)
cipher = rsa_encrypt(65, n, e)
plain = rsa_decrypt(cipher, n, d)
```

## Hardening checklist

- [x] Use OAEP for encryption.
- [x] Use PSS for signatures.
- [x] Use constant-time modular exponentiation.
- [ ] Keys generated in an HSM or secure enclave.
- [ ] Rotate keys and revoke old certs.
- [ ] Ensure error messages are uniform.

## Footnote

[^1]: If you are tempted to implement RSA yourself, stop and use a well-tested library instead.

## Further reading

- [RFC 8017: PKCS #1](https://www.rfc-editor.org/rfc/rfc8017)
- [RSA blinding](https://en.wikipedia.org/wiki/Blinding_(cryptography))
- [Padding oracle attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack)
