# Contribution Guidelines

- Please file an issue before creating a PR for anything other than a non-breaking bug fix.
- Ensure every change comes with a test if possible. The project maintains a test coverage gate and your PRs will fail if they drop coverage below the existing threshold.

# Development tips

- The library has an extensive test suite that is a combination of regular JUnit 5 tests, a set of generated tests from the [upstream test vectors](https://github.com/C2SP/CCTV/tree/main/age), and an optional mutation testing suite using [Pitest](https://pitest.org/).
- Pitest forks a new JVM per run, which can be too heavy for most machines. Pass the `-PslimTests` flag to `gradle check` to skip Pitest and run all other tests.
