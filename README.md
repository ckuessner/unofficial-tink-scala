# Unofficial port of tink-java to Scala 3 (for use with Scala.js)
This is an **unofficial** port of (parts of) Googles [Tink](https://developers.google.com/tink) crypto library to Scala / Scala.js.
The goal is to provide a common interface for cryptographic primitives for Scala on the JVM and Scala.js.
However, you probably shouldn't use this project in production.
It is likely that there are bugs that were introduced while porting the Java library to Scala.

The regular Tink APIs are in the root module, while the raw crypto APIs are refactored out in the "subtle" module.

### The following primitives are supported:
- AEAD
  - XChaCha20Poly1305
- Digital Signatures
  - ED25519

Most of the features of Tinks Java library aren't supported (like protobuf serialization, AES, hybrid encryption, …)

The code is based on the code in `java_src/` from commit eaa48d17fc1d2d04f548a378ce20d994cac0db1f from https://github.com/google/tink.git
as well as  the release 1.76 of the Bouncy Castle Crypto Package for Java taken from https://github.com/bcgit/bc-java.