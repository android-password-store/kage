# Throughput benchmarks

Run from the repository root with Java 17 or newer:

```sh
./gradlew :benchmarks:jmh
```

JMH reports operations per second, with one complete API call per operation. Defaults
are one thread, two JVM forks, three 1-second warmup iterations and five 1-second
measurement iterations per case, with a fixed 1 GiB heap. Results, including JVM
metadata, scores and error estimates, go to `benchmarks/build/results/jmh/baseline.json`.
There are no performance thresholds. Keep results alongside the Git revision and
machine/OS details when comparing runs; use an idle machine and the same JDK.
The full suite takes roughly 15 minutes, depending on the machine.

For a quick execution/fixture check (not a reliable baseline):

```sh
./gradlew :benchmarks:jmh -PjmhSmoke
```

Smoke mode uses one fork and one 200 ms iteration each for warmup and measurement,
and writes `benchmarks/build/results/jmh/smoke.json` instead of replacing the baseline.
Filter methods and/or the crypto fixture for a focused baseline:

```sh
./gradlew :benchmarks:jmh -PjmhInclude='.*AgeKeyFileParsingBenchmark.*'
./gradlew :benchmarks:jmh -PjmhInclude='.*AgeThroughputBenchmark.*' -PjmhFixture=x25519
```

## Vectors

The harness packages these existing successful CCTV vectors from
`src/test/resources/CCTV/age/testdata/`; it does not copy or modify them:

| Vector | Plaintext bytes | Purpose |
| --- | ---: | --- |
| `x25519` | 3 | Small binary X25519 message; setup and key-wrapping cost |
| `armor_x25519` | 3 | ASCII armor parsing and streaming output |
| `hybrid` | 3 | ML-KEM-768/X25519 hybrid key operations |
| `scrypt` | 3 | Passphrase encryption, using the vector's work factor **10** |
| `stream_empty_payload` | 0 | Empty payload and authenticated final chunk |
| `stream_last_chunk_full` | 65,536 | Exactly one full 64 KiB chunk |
| `stream_two_chunks` | 131,072 | Two full chunks |
| `stream_257_chunks` | 16,777,217 | 256 full chunks plus a one-byte final chunk |

The scrypt case deliberately matches its vector, not the library's default work
factor. Its score is not representative of default-cost passphrase encryption.

## Measurement boundaries

- Resource reads, CCTV metadata parsing, zlib decompression, key decoding, recipient
  derivation and SHA-256 plaintext verification happen only in trial setup, outside
  warmup and measurement. No benchmark reads a filesystem path or classpath resource.
- Each invocation creates fresh in-memory input/output streams. Buffer allocation,
  API-internal randomness and crypto setup remain timed: these are public API
  throughput measurements, not isolated cipher benchmarks. Outputs are returned to
  JMH to prevent dead-code elimination; lazy encrypted/decrypted streams are fully
  read and closed inside the timed method.
- `encrypt`, `encryptStream`, `encryptReader`, `decryptAgeFile`, `decryptStream` and
  `extractHeader` cover the primary in-memory/streaming APIs and header parsing.
  `encryptStream` emits armor for `armor_x25519`; `encrypt` and `encryptReader` always
  produce binary output. `decryptStream` uses the original CCTV ciphertext.
- There is no public `AgeFile` parser, so trial setup creates an `AgeFile` from the
  vector's verified plaintext and checks its round trip for `decryptAgeFile`.
- The four key-file parsing cases call public `Age.parseIdentities` and
  `Age.parseRecipients` on single X25519 or hybrid key strings derived from the
  corresponding vectors. Fresh `StringReader`/`BufferedReader` creation is timed;
  resource reading and public-key derivation are not.
- Scores count messages or key files, not bytes. For payload-processing methods,
  multiply ops/s by the table's plaintext size to obtain bytes/s. Header extraction
  does not process the payload and should not be converted this way.

The separate Java-only benchmark module uses only public library APIs and excludes
unit-test classes and dependencies from its JMH harness. Benchmarks are opt-in and
are not attached to `test` or `check`.
