# 🚧 kage 🚧 ![Maven Central](https://img.shields.io/maven-central/v/com.github.android-password-store/kage?style=flat-square&label=Latest%20version)

<p align="center"><img alt="The age logo, an wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://user-images.githubusercontent.com/1225294/132245842-fda4da6a-1cea-4738-a3da-2dc860861c98.png"></p>

kage is a work-in-progress implementation of the [age encryption protocol] for Kotlin/JVM and Android. The [reference Go implementation] and the third-party [Rust implementation] are being used as reference for the development of the library.

## Download

An initial alpha release is available on [Maven Central]

```kotlin
// build.gradle.kts
dependencies {
  implementation("com.github.android-password-store:kage:0.2.0")
}
```

Builds from the development branch can be obtained from [Sonatype's snapshots repository].

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories {
    exclusiveContent {
      forRepository { maven("https://oss.sonatype.org/content/repositories/snapshots") }
      filter { includeModule("com.github.android-password-store", "kage") }
    }
  }
}
```

```kotlin
// build.gradle.kts
dependencies {
  implementation("com.github.android-password-store:kage:0.2.0-SNAPSHOT")
}
```

## Goals

- Provide a library that can generate and parse age keys, as well as encrypt or decrypt bytes using said keys.
- Achieve parity with the [reference Go implementation]: everything that can be done with the `age` library should also be possible with the `kage` APIs

The current completion status can be tracked through [this MVP checklist](https://github.com/android-password-store/kage/issues/15)

## Non-goals

These can evolve over time, but for now the following are non-goals for our work on kage.

- Offer a user interface of any kind (CLI/GUI): The kage project intends to only be a library for other applications to build on
- Support plugins: The upstream implementation of plugins relies on binaries in `$PATH`, which is [impractical for mobile](https://github.com/FiloSottile/age/discussions/365#discussioncomment-1711442).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[age encryption protocol]: https://age-encryption.org/v1
[reference go implementation]: https://github.com/FiloSottile/age
[rust implementation]: https://github.com/str4d/rage
[sonatype's snapshots repository]: https://oss.sonatype.org/content/repositories/snapshots
[maven central]: https://central.sonatype.com/
