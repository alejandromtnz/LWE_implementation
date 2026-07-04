"""Nucleo de un esquema LWE simplificado para experimentos.

El objetivo de este modulo no es ofrecer una implementacion criptografica
lista para produccion, sino una version pequena y controlable del cifrado de
Regev. La estructura permite medir de forma directa como el ruido acumulado
afecta a la correccion del descifrado.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Optional

import numpy as np
from numpy.typing import NDArray


IntArray = NDArray[np.int64]


@dataclass(frozen=True)
class PublicKey:
    """Clave publica LWE: matriz A y vector b = A s + e mod q."""

    A: IntArray
    b: IntArray


@dataclass(frozen=True)
class SecretKey:
    """Clave privada: vector secreto s."""

    s: IntArray


@dataclass(frozen=True)
class KeyPair:
    """Par de claves.

    El vector error se conserva solo para analizar el ruido acumulado en los
    experimentos. En un esquema real no se trataria como salida publica.
    """

    public: PublicKey
    secret: SecretKey
    error: IntArray


@dataclass(frozen=True)
class Ciphertext:
    """Criptograma LWE simplificado.

    El criptograma propiamente dicho es (u, v). El vector r se guarda para
    poder medir e^T r durante los experimentos.
    """

    u: IntArray
    v: int
    r: IntArray


def centered_mod(x: int | NDArray[np.integer], q: int) -> int | IntArray:
    """Representa residuos modulo q en el intervalo centrado alrededor de 0."""

    values = np.asarray(x, dtype=np.int64)
    centered = ((values + q // 2) % q) - q // 2
    if np.isscalar(x):
        return int(centered)
    return centered.astype(np.int64)


def modular_distance(x: int, target: int, q: int) -> int:
    """Distancia circular entre x y target modulo q."""

    return abs(int(centered_mod(x - target, q)))


def is_prime(q: int) -> bool:
    """Test determinista sencillo, suficiente para los modulos pequenos usados."""

    if q < 2:
        return False
    if q == 2:
        return True
    if q % 2 == 0:
        return False
    divisor = 3
    while divisor * divisor <= q:
        if q % divisor == 0:
            return False
        divisor += 2
    return True


def solve_linear_system_mod_prime(A: IntArray, b: IntArray, q: int) -> Optional[IntArray]:
    """Resuelve A s = b (mod q) mediante eliminacion gaussiana exacta.

    La funcion trabaja sobre el cuerpo Z_q, por lo que requiere q primo. Si el
    sistema no tiene rango completo o no es consistente, devuelve None.
    """

    if not is_prime(q):
        raise ValueError("La eliminacion exacta implementada requiere q primo.")

    A_mod = np.asarray(A, dtype=np.int64) % q
    b_mod = np.asarray(b, dtype=np.int64).reshape(-1, 1) % q
    if A_mod.ndim != 2:
        raise ValueError("A debe ser una matriz.")
    if A_mod.shape[0] != b_mod.shape[0]:
        raise ValueError("Dimensiones incompatibles entre A y b.")

    m, n = A_mod.shape
    augmented = np.concatenate([A_mod, b_mod], axis=1)
    row = 0
    pivots: list[int] = []

    for col in range(n):
        pivot = None
        for candidate in range(row, m):
            if augmented[candidate, col] % q != 0:
                pivot = candidate
                break
        if pivot is None:
            continue

        if pivot != row:
            augmented[[row, pivot]] = augmented[[pivot, row]]

        inv = pow(int(augmented[row, col]), -1, q)
        augmented[row, :] = (augmented[row, :] * inv) % q

        for other in range(m):
            if other == row:
                continue
            factor = int(augmented[other, col] % q)
            if factor:
                augmented[other, :] = (augmented[other, :] - factor * augmented[row, :]) % q

        pivots.append(col)
        row += 1
        if row == m:
            break

    if len(pivots) < n:
        return None

    solution = np.zeros(n, dtype=np.int64)
    for pivot_row, pivot_col in enumerate(pivots):
        solution[pivot_col] = int(augmented[pivot_row, n] % q)

    residual = (A_mod @ solution - b_mod[:, 0]) % q
    if np.any(residual != 0):
        return None
    return solution


class LWEScheme:
    """Esquema de cifrado LWE simplificado tipo Regev.

    Parametros:
        n: dimension del secreto.
        m: numero de muestras publicas. Si no se indica, se toma m = 2n.
        q: modulo de trabajo.
        sigma: desviacion tipica del error gaussiano discreto.
        B: si se indica, usa error uniforme en [-B, B] en vez de sigma.
        seed/rng: fuente de aleatoriedad reproducible.
    """

    def __init__(
        self,
        n: int,
        q: int,
        sigma: float = 0.0,
        m: Optional[int] = None,
        B: Optional[int] = None,
        seed: Optional[int] = None,
        rng: Optional[np.random.Generator] = None,
    ) -> None:
        if n <= 0:
            raise ValueError("n debe ser positivo.")
        if q <= 2:
            raise ValueError("q debe ser mayor que 2.")
        if m is not None and m <= 0:
            raise ValueError("m debe ser positivo.")
        if sigma < 0:
            raise ValueError("sigma no puede ser negativo.")
        if B is not None and B < 0:
            raise ValueError("B no puede ser negativo.")
        if B is not None and sigma != 0:
            raise ValueError("Usa sigma o B para el ruido, no ambos a la vez.")

        self.n = int(n)
        self.m = int(m) if m is not None else 2 * int(n)
        self.q = int(q)
        self.sigma = float(sigma)
        self.B = int(B) if B is not None else None
        self.message_gap = self.q // 2
        self.rng = rng if rng is not None else np.random.default_rng(seed)

    @property
    def noise_description(self) -> str:
        if self.B is not None:
            return f"uniforme[-{self.B},{self.B}]"
        return f"gaussiano sigma={self.sigma:g}"

    def sample_error(self, size: int | tuple[int, ...]) -> IntArray:
        """Muestrea el error discreto usado en la clave publica."""

        if self.B is not None:
            if self.B == 0:
                return np.zeros(size, dtype=np.int64)
            return self.rng.integers(-self.B, self.B + 1, size=size, dtype=np.int64)

        if self.sigma == 0:
            return np.zeros(size, dtype=np.int64)
        return np.rint(self.rng.normal(0.0, self.sigma, size=size)).astype(np.int64)

    def keygen(self) -> KeyPair:
        """Genera A, s, e y b = A s + e mod q."""

        A = self.rng.integers(0, self.q, size=(self.m, self.n), dtype=np.int64)
        s = self.rng.integers(0, self.q, size=self.n, dtype=np.int64)
        e = self.sample_error(self.m)
        b = (A @ s + e) % self.q
        return KeyPair(public=PublicKey(A=A, b=b), secret=SecretKey(s=s), error=e)

    def encrypt_bit(self, public_key: PublicKey, mu: int) -> Ciphertext:
        """Cifra un bit mu en {0, 1}.

        Se usa una combinacion binaria aleatoria de las muestras publicas:
            u = A^T r
            v = b^T r + mu * floor(q/2)
        Por tanto, al descifrar queda d = mu * floor(q/2) + e^T r mod q.
        """

        if mu not in (0, 1):
            raise ValueError("Este esquema simplificado solo cifra bits 0/1.")
        if public_key.A.shape != (self.m, self.n):
            raise ValueError("La matriz A no coincide con los parametros del esquema.")
        if public_key.b.shape != (self.m,):
            raise ValueError("El vector b no coincide con los parametros del esquema.")

        r = self.rng.integers(0, 2, size=self.m, dtype=np.int64)
        u = (public_key.A.T @ r) % self.q
        v = int((public_key.b @ r + int(mu) * self.message_gap) % self.q)
        return Ciphertext(u=u.astype(np.int64), v=v, r=r)

    def decryption_value(self, secret_key: SecretKey, ciphertext: Ciphertext) -> int:
        """Devuelve d = v - <u, s> mod q."""

        if secret_key.s.shape != (self.n,):
            raise ValueError("El secreto no coincide con los parametros del esquema.")
        return int((ciphertext.v - secret_key.s @ ciphertext.u) % self.q)

    def decrypt_from_value(self, d: int) -> int:
        """Decide el bit por cercania de d a 0 o a floor(q/2)."""

        dist_zero = modular_distance(d, 0, self.q)
        dist_half = modular_distance(d, self.message_gap, self.q)
        return 1 if dist_half < dist_zero else 0

    def decrypt_bit(self, secret_key: SecretKey, ciphertext: Ciphertext) -> int:
        """Descifra un criptograma y devuelve 0 o 1."""

        return self.decrypt_from_value(self.decryption_value(secret_key, ciphertext))

    def accumulated_error(self, key_error: IntArray, r: IntArray) -> int:
        """Calcula el ruido acumulado centrado e^T r mod q."""

        if key_error.shape != (self.m,) or r.shape != (self.m,):
            raise ValueError("Dimensiones incompatibles para e y r.")
        return int(centered_mod(int(key_error @ r), self.q))

    def public_key_size_bytes(self) -> int:
        """Tamano aproximado de (A, b), codificando cada entrada modulo q."""

        bits_per_entry = math.ceil(math.log2(self.q))
        entries = self.m * self.n + self.m
        return math.ceil(entries * bits_per_entry / 8)
