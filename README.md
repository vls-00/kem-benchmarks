# KEM Benchmark Suite for CPU Time Benchmarks

This repository provides a unified methodology for benchmarking Key Encapsulation Mechanisms (KEMs) using CPU time in milliseconds instead of CPU cycles because most official implementations report performance in CPU cycles.

Although cycles can be converted to time mathematically with the following formulas:

$$
\text{time (ms)} = \frac{\text{cycles}}{\text{CPU frequency (Hz)}} \times 1000
$$

$$
\text{time (ms)} = \frac{\text{cycles}}{\text{frequency (GHz)} \times 10^6}
$$

that approach depends on assumptions about CPU frequency, scheduling behavior, and measurement conditions. This project focuses on direct time-based measurement to produce results that are easier to interpret and compare in practical environments.

The repository includes:

- A standalone benchmark for Elliptic Curve Diffie-Hellman (ECDH);
- A modified ML-KEM benchmark based on the official implementation;
- Build and execution instructions for HQC-KEM;
- Build and execution instructions for Classic McEliece;
- A practical workflow for measuring KEM execution time in milliseconds.

## Motivation

Benchmarking cryptographic algorithms in CPU cycles is common in official implementations and academic codebases. However, for a thesis or practical systems evaluation, reporting execution time in milliseconds is often easier to understand and more directly applicable to real-world environments.

This repository was created to support time-based benchmarking of multiple KEMs using either custom benchmark code or modified official benchmark implementations.

## Benchmarking Methodology

The goal of this project is to measure execution time directly in milliseconds rather than derive it from cycle counts.

To improve consistency, it is recommended to:

- Use release builds with compiler optimizations enabled;
- Benchmark key generation, encapsulation, and decapsulation separately;
- Run enough iterations to reduce noise;
- Execute benchmarks on an otherwise idle system;
- Pin the benchmark to a single CPU core when comparing algorithms;
- Disable CPU frequency scaling or turbo boost when high reproducibility is required.

Example of running a benchmark on a fixed core:

```bash
taskset -c 0 ./benchmark_binary
```

## Elliptic Curve Diffie-Hellman (ECDH)

A complete ECDH benchmark is provided in the `ecdh_kem_bench.c` file. It uses the OpenSSL implementation and measures execution time in milliseconds.

Build and run:

```bash
gcc -O2 -Wall -Wextra -std=c11 ecdh_kem_bench.c -o ecdh_kem_bench -lcrypto
./ecdh_kem_bench
```

This benchmark is intended to provide a classical baseline for comparison against post-quantum KEMs.

## ML-KEM

The official ML-KEM implementation is hosted at: [https://github.com/pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native)

The official benchmark code reports results in CPU cycles. In this repository, the `test/bench/bench_mlkem.c` benchmark file was modified to replace the official corresponding file and measure CPU time in milliseconds.

### Instructions

1. Clone the official repository:

```bash
git clone https://github.com/pq-code-package/mlkem-native
cd mlkem-native
```

2. Replace the official benchmark file with the modified version from this repository:

```bash
cp /path/to/this/repository/bench_mlkem.c test/bench/bench_mlkem.c
```

3. Build and run the benchmark:

```bash
make build
make tests
python3 ./scripts/tests bench -c PMU --ru
```

## HQC-KEM

The official HQC implementation is hosted at: [https://gitlab.com/pqc-hqc/hqc/](https://gitlab.com/pqc-hqc/hqc/)

The HQC project already supports benchmarking in CPU time, but building and running the benchmarks can be slightly tricky. The following commands can be used for both the reference and optimized implementations.

### Reference Implementation

```bash
rm -rf build-ref
cmake -S . -B build-ref \
  -DCMAKE_BUILD_TYPE=Release \
  -DHQC_ARCH=ref
cmake --build build-ref -j$(nproc)
ctest --test-dir build-ref -j$(nproc)

./build-ref/tests/bench/benchmark_kem_hqc_1
./build-ref/tests/bench/benchmark_kem_hqc_3
./build-ref/tests/bench/benchmark_kem_hqc_5
```

### Optimized Implementation (AVX2 / AVX256)

```bash
rm -rf build-avx256
cmake -S . -B build-avx256 \
  -DCMAKE_BUILD_TYPE=Release \
  -DHQC_ARCH=x86_64 \
  -DHQC_X86_IMPL=avx256
cmake --build build-avx256 -j$(nproc)
ctest --test-dir build-avx256 -j$(nproc)

./build-avx256/tests/bench/benchmark_kem_hqc_1
./build-avx256/tests/bench/benchmark_kem_hqc_3
./build-avx256/tests/bench/benchmark_kem_hqc_5
```

## Classic McEliece

The official Classic McEliece implementation is available at: [https://lib.mceliece.org/download.html](https://lib.mceliece.org/download.html)

Classic McEliece supports benchmarking in CPU time, but installation requires a few supporting libraries. The following instructions work on Debian-based systems to compile and benchmark Classic McEliece KEM:

```bash
# Install libcpucycles
wget -m https://cpucycles.cr.yp.to/libcpucycles-latest-version.txt
version=$(cat cpucycles.cr.yp.to/libcpucycles-latest-version.txt)
wget -m https://cpucycles.cr.yp.to/libcpucycles-$version.tar.gz
tar -xzf cpucycles.cr.yp.to/libcpucycles-$version.tar.gz
cd libcpucycles-$version
./configure && make -j8 install

# Install librandombytes
wget -m https://randombytes.cr.yp.to/librandombytes-latest-version.txt
version=$(cat randombytes.cr.yp.to/librandombytes-latest-version.txt)
wget -m https://randombytes.cr.yp.to/librandombytes-$version.tar.gz
tar -xzf randombytes.cr.yp.to/librandombytes-$version.tar.gz
cd librandombytes-$version
./configure && make -j8 install

# Install libmceliece
wget -m https://lib.mceliece.org/libmceliece-latest-version.txt
version=$(cat lib.mceliece.org/libmceliece-latest-version.txt)
wget -m https://lib.mceliece.org/libmceliece-$version.tar.gz
tar -xzf lib.mceliece.org/libmceliece-$version.tar.gz
cd libmceliece-$version
./configure && make -j8 install

# Optional dependency for additional analysis
sudo apt install valgrind

# Run benchmark
LD_LIBRARY_PATH="$PWD/build/amd64/package/lib:$LD_LIBRARY_PATH" mceliece-speed
```

## Notes

- Use the same machine and system conditions for all algorithms when collecting results.
- Record compiler version, CPU model, operating system, and optimization flags.
- Run multiple repetitions and report average values.
- If possible, also record variance or standard deviation.
- Keep benchmark methodology identical across all tested KEMs.
