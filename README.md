# Implementacion practica LWE simplificada

Esta carpeta contiene una implementacion experimental, pequena y reproducible
de un esquema de cifrado basado en LWE. No implementa Kyber, Dilithium,
FrodoKEM ni ningun esquema moderno completo. La finalidad es estudiar a escala
controlada el papel del ruido y de parametros como `n`, `m` y `q`.

## Estructura

- `lwe_scheme.py`: nucleo del esquema LWE simplificado tipo Regev.
- `experiments.py`: experimentos, medicion de tiempos e intervalos de confianza.
- `plots.py`: generacion de graficas con matplotlib.
- `run_experiments.py`: script principal.
- `results/`: CSV y figuras generadas.
- `requirements.txt`: dependencias Python.

## Esquema implementado

La generacion de claves toma:

```text
A <- Z_q^{m x n}
s <- Z_q^n
e <- ruido discreto
b = A s + e mod q
```

Para cifrar un bit `mu` se elige `r` binario y se calcula:

```text
u = A^T r mod q
v = b^T r + mu * floor(q/2) mod q
```

El descifrado calcula:

```text
d = v - <u,s> mod q
```

y decide si `d` esta mas cerca de `0` o de `floor(q/2)`. Asi, el termino que
controla el fallo es el ruido acumulado `e^T r`.

## Experimentos

El script genera:

- comparacion sin ruido frente a ruido, incluyendo recuperacion exacta de `s`
  por eliminacion gaussiana modular cuando `sigma = 0`;
- barrido de ruido `sigma`;
- efecto de `q` con `sigma` fijo;
- efecto de `n` sobre tiempos y tamano aproximado de clave publica;
- histogramas de `d = v - <u,s> mod q` para `mu=0` y `mu=1`.

Hay dos variantes del histograma:

- `histogram_d_fixed_key`: usa una unica clave fija. Muestra el
  comportamiento condicionado a una realizacion concreta del vector de error
  `e`; por eso el ruido acumulado puede aparecer desplazado si `sum(e)` no es
  cercano a cero.
- `histogram_d_multikey`: promedia sobre varias claves independientes. Es la
  version mas adecuada como visualizacion pedagogica del esquema, porque el
  ruido relativo al centro esperado se concentra alrededor de cero al promediar
  distintas claves.

La eliminacion gaussiana se hace exactamente en `Z_q`, por lo que el ataque
lineal incluido requiere que `q` sea primo. Los parametros por defecto usan
modulos primos pequenos.

## Ejecucion

Desde esta carpeta:

```bash
source .venv/bin/activate
python run_experiments.py
```

Para una comprobacion rapida:

```bash
source .venv/bin/activate
python run_experiments.py --quick
```

Para generar mas muestras de cara al TFG:

```bash
source .venv/bin/activate
python run_experiments.py --trials 1000 --repeats 30 --hist-samples 10000
```

Los CSV y las figuras se guardan en `results/`.
