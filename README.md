# RSA vs Post-Quantum Cryptography — Practical Comparison (CRYSTALS-Kyber)

Proof-of-concept implementation and **reproducible benchmarks** comparing a classical **RSA+AES hybrid** against the lattice-based post-quantum KEM **CRYSTALS-Kyber** (Kyber512/768/1024).

This repository contains the code, scripts, results and figures used for my Final Year Project dissertation:  
**“RSA vs. Post-Quantum Cryptography: Practical Comparison of RSA+AES and CRYSTALS-Kyber.”**

- **Author:** Ademola Baruwa (N1142033)  
- **Dissertation:** `docs/DissFinal.docx` (and/or PDF if you export it)

---

## TL;DR

- Implemented **RSA (OAEP) + AES-EAX** for a classical hybrid and **CRYSTALS-Kyber** for a PQ KEM.
- Benchmarked **key generation**, **encapsulation/decapsulation** (or RSA key-wrap/un-wrap) and **AES bulk** times across payloads **224 B → 500 KB**.
- **100 runs per scenario**, CPU/time profiled with `psutil`, results exported to CSV and plotted.
- Typical result (hardware-dependent): **Kyber keygen = milliseconds (~0.002–0.01 s)** vs **RSA-2048 ≈ 0.8–1.0 s**. Kyber KEM ops are single-digit ms; AES bulk stays sub-ms to a few ms.

---

## Quickstart

> Commands shown for macOS/Linux. On Windows, adapt the venv activation command.

```bash
# 1) Clone
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# 2) Create & activate virtual env
python3 -m venv .venv
source .venv/bin/activate

# 3) Install deps
pip install -r requirements.txt


python main.py \
  --algos rsa,kyber512 \
  --files data/small_text_sample.txt \
  --runs 1 \
  --out data/check_results.csv

```Full benchmarks (100 runs, multiple algos/files)
python main.py \
  --algos rsa,kyber512,kyber768,kyber1024 \
  --files data/small_text_sample.txt,data/large_text_sample.txt \
  --runs 100 \
  --out data/full_results.csv



