<p align="center"><img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://user-images.githubusercontent.com/1225294/132245842-fda4da6a-1cea-4738-a3da-2dc860861c98.png"></p>

# 🚧 kage 🚧

kage is a work-in-progress implementation of the [age encryption protocol] for Kotlin/JVM and Android. The [reference Go implementation] and the third-party [Rust implementation] are being used as reference for the development of the library.

## Goals

- Provide a library that can generate and parse age keys, as well as encrypt or decrypt text using said keys.
- Achieve parity with the [reference Go implementation]: everything that can be done with the `age` library should also be possible with the `kage` APIs

## Non-goals

These can evolve over time, but for now the following are non-goals for our work on kage.

- Offer a user interface of any kind (CLI/GUI): The kage project intends to only be a library for other applications to build on
- Support plugins: The upstream implementation of plugins relies on binaries in `$PATH`, which is [impractical for mobile](https://github.com/FiloSottile/age/discussions/365#discussioncomment-1711442).

[age encryption protocol]: https://age-encryption.org/v1
[reference go implementation]: https://github.com/FiloSottile/age
[rust implementation]: https://github.com/str4d/rage
