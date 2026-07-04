# LWE Implementation — Bachelor's Thesis (TFG)

Final-degree project (TFG) on **post-quantum cryptography**: a small, reproducible
experimental implementation of a simplified **LWE** (Learning With Errors)
encryption scheme, used to study — at a controlled scale — the role of noise and
of parameters such as `n`, `m` and `q`.

This repository gathers the written thesis, the defence slides and the code with
its results.

## Contents

| | |
|---|---|
| 📄 **Thesis** | [`TFG_LWE.pdf`](./TFG_LWE.pdf) — full written report |
| 🖥️ **Slides** | [`presentacion_LWE.pdf`](./presentacion_LWE.pdf) — defence presentation |
| 💻 **Code & results** | [`src/`](./src) — Python implementation, experiments and generated figures |

> Rename the PDF/slide files above to match whatever you upload (e.g.
> `presentacion_LWE.pptx`), and update these links accordingly.

## About the project

The scheme is a Regev-style simplified LWE encryption. It does **not** implement
Kyber, Dilithium, FrodoKEM or any complete modern scheme — the goal is didactic:
to observe empirically how the accumulated noise `eᵀr` governs the decryption
failure rate, and how it depends on the noise level `σ`, the modulus `q` and the
dimension `n`.

The experiments include: noiseless vs. noisy comparison (with exact recovery of
`s` by modular Gaussian elimination when `σ = 0`), a noise sweep over `σ`, the
effect of `q`, the effect of `n` on runtime and public-key size, and histograms
of `d = v − ⟨u,s⟩ mod q`.

## Running the code

See [`src/README.md`](./src/README.md) for full instructions. In short:

```bash
cd src
pip install -r requirements.txt
python run_experiments.py            # add --quick for a fast check
```

CSVs and figures are written to `src/results/`.

---

**Author:** Alejandro Martínez Ronda
