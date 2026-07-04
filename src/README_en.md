# Practical Implementation of a Simplified LWE Scheme

This folder contains a small, reproducible experimental implementation of an
LWE-based encryption scheme. It does **not** implement Kyber, Dilithium, FrodoKEM
or any complete modern scheme. The goal is to study, at a controlled scale, the
role of noise and of parameters such as `n`, `m` and `q`.

## Structure

- `lwe_scheme.py`: core of the simplified Regev-style LWE scheme.
- `experiments.py`: experiments, timing measurements and confidence intervals.
- `plots.py`: figure generation with matplotlib.
- `run_experiments.py`: main script.
- `results/`: generated CSVs and figures.
- `requirements.txt`: Python dependencies.

## Implemented scheme

Key generation takes:

```text
A <- Z_q^{m x n}
s <- Z_q^n
e <- discrete noise
b = A s + e mod q
```

To encrypt a bit `mu`, a binary `r` is chosen and:

```text
u = A^T r mod q
v = b^T r + mu * floor(q/2) mod q
```

Decryption computes:

```text
d = v - <u,s> mod q
```

and decides whether `d` is closer to `0` or to `floor(q/2)`. The term that governs
the failure is therefore the accumulated noise `e^T r`.

## Experiments

The script generates:

- a noiseless vs. noisy comparison, including exact recovery of `s` by modular
  Gaussian elimination when `sigma = 0`;
- a noise sweep over `sigma`;
- the effect of `q` with fixed `sigma`;
- the effect of `n` on runtime and approximate public-key size;
- histograms of `d = v - <u,s> mod q` for `mu=0` and `mu=1`.

There are two histogram variants:

- `histogram_d_fixed_key`: uses a single fixed key. It shows the behaviour
  conditioned on one concrete realisation of the error vector `e`; the accumulated
  noise may therefore appear shifted if `sum(e)` is not close to zero.
- `histogram_d_multikey`: averages over several independent keys. This is the more
  suitable variant as a pedagogical visualisation, because the noise relative to
  the expected centre concentrates around zero when averaging across different
  keys.

Gaussian elimination is performed exactly in `Z_q`, so the included linear attack
requires `q` to be prime. The default parameters use small prime moduli.

## Running

From this folder:

```bash
source .venv/bin/activate
python run_experiments.py
```

For a quick check:

```bash
source .venv/bin/activate
python run_experiments.py --quick
```

To generate more samples for the thesis:

```bash
source .venv/bin/activate
python run_experiments.py --trials 1000 --repeats 30 --hist-samples 10000
```

CSVs and figures are saved to `results/`.
