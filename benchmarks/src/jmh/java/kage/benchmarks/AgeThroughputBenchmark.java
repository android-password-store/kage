/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.benchmarks;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.InflaterInputStream;
import kage.Age;
import kage.Identity;
import kage.Recipient;
import kage.crypto.mlkem.MlKem768X25519Identity;
import kage.crypto.scrypt.ScryptIdentity;
import kage.crypto.scrypt.ScryptRecipient;
import kage.crypto.x25519.X25519Identity;
import kage.format.AgeFile;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class AgeThroughputBenchmark {
  @Param({
    "x25519",
    "armor_x25519",
    "hybrid",
    "scrypt",
    "stream_empty_payload",
    "stream_last_chunk_full",
    "stream_two_chunks",
    "stream_257_chunks"
  })
  public String fixtureName;

  private byte[] plaintext;
  private byte[] ciphertext;
  private List<Identity> identities;
  private List<Recipient> recipients;
  private boolean armored;
  private AgeFile ageFile;

  @Setup(Level.Trial)
  public void setup() throws Exception {
    Fixture fixture = Fixture.load(fixtureName);
    armored = fixture.armored;
    int scryptWorkFactor = fixture.scryptWorkFactor;
    identities = decodeIdentities(fixture.metadata, scryptWorkFactor);
    recipients = deriveRecipients(identities, fixture.metadata, scryptWorkFactor);
    ciphertext = fixture.ciphertext;

    ByteArrayOutputStream decoded = new ByteArrayOutputStream();
    Age.decryptStream(identities, new ByteArrayInputStream(ciphertext), decoded);
    plaintext = decoded.toByteArray();
    if (!HexFormat.of()
        .formatHex(MessageDigest.getInstance("SHA-256").digest(plaintext))
        .equals(fixture.expectedHash)) {
      throw new IllegalStateException("CCTV plaintext SHA-256 mismatch");
    }

    // AgeFile is generated from the validated plaintext because AgeFile parsing is not public API.
    ageFile = Age.encrypt(recipients, new ByteArrayInputStream(plaintext));
    try (InputStream decrypted = Age.decrypt(identities, ageFile)) {
      requireEqual(plaintext, decrypted.readAllBytes(), "generated AgeFile roundtrip");
    }
  }

  @Benchmark
  public AgeFile encrypt() {
    return Age.encrypt(recipients, new ByteArrayInputStream(plaintext));
  }

  @Benchmark
  public ByteArrayOutputStream encryptStream() {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    Age.encryptStream(recipients, new ByteArrayInputStream(plaintext), output, armored);
    return output;
  }

  @Benchmark
  public byte[] encryptReader() throws IOException {
    try (InputStream encrypted =
        Age.encryptReader(recipients, new ByteArrayInputStream(plaintext))) {
      return encrypted.readAllBytes();
    }
  }

  @Benchmark
  public byte[] decryptAgeFile() throws IOException {
    try (InputStream decrypted = Age.decrypt(identities, ageFile)) {
      return decrypted.readAllBytes();
    }
  }

  @Benchmark
  public ByteArrayOutputStream decryptStream() {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    Age.decryptStream(identities, new ByteArrayInputStream(ciphertext), output);
    return output;
  }

  @Benchmark
  public byte[] extractHeader() {
    return Age.extractHeader(new ByteArrayInputStream(ciphertext));
  }

  private static List<Identity> decodeIdentities(String metadata, int scryptWorkFactor) {
    List<Identity> result = new ArrayList<>();
    String passphrase = null;
    for (String line : metadata.split("\\R")) {
      if (line.startsWith("identity: ")) {
        String encoded = line.substring("identity: ".length());
        if (encoded.startsWith("AGE-SECRET-KEY-PQ-")) {
          result.add(MlKem768X25519Identity.Companion.decode(encoded));
        } else {
          result.add(X25519Identity.Companion.decode(encoded));
        }
      } else if (line.startsWith("passphrase: ")) {
        passphrase = line.substring("passphrase: ".length());
      }
    }
    if (passphrase != null)
      result.add(new ScryptIdentity(passphrase.getBytes(StandardCharsets.UTF_8), scryptWorkFactor));
    if (result.isEmpty()) throw new IllegalStateException("Fixture has no identity");
    return List.copyOf(result);
  }

  private static List<Recipient> deriveRecipients(
      List<Identity> identities, String metadata, int scryptWorkFactor) {
    List<Recipient> result = new ArrayList<>();
    for (Identity identity : identities) {
      if (identity instanceof X25519Identity) {
        result.add(((X25519Identity) identity).recipient());
      } else if (identity instanceof MlKem768X25519Identity) {
        result.add(((MlKem768X25519Identity) identity).recipient());
      }
    }
    for (String line : metadata.split("\\R")) {
      if (line.startsWith("passphrase: ")) {
        result.add(
            new ScryptRecipient(
                line.substring("passphrase: ".length()).getBytes(StandardCharsets.UTF_8),
                scryptWorkFactor));
      }
    }
    if (result.isEmpty()) throw new IllegalStateException("Fixture has no usable recipient");
    return List.copyOf(result);
  }

  private static void requireEqual(byte[] expected, byte[] actual, String operation) {
    if (!MessageDigest.isEqual(expected, actual)) {
      throw new IllegalStateException(operation + " plaintext mismatch");
    }
  }

  private static final class Fixture {
    final String metadata;
    final byte[] ciphertext;
    final String expectedHash;
    final boolean armored;
    final int scryptWorkFactor;

    private Fixture(
        String metadata,
        byte[] ciphertext,
        String expectedHash,
        boolean armored,
        int scryptWorkFactor) {
      this.metadata = metadata;
      this.ciphertext = ciphertext;
      this.expectedHash = expectedHash;
      this.armored = armored;
      this.scryptWorkFactor = scryptWorkFactor;
    }

    static Fixture load(String name) throws IOException {
      String resource = "/CCTV/age/testdata/" + name;
      byte[] bytes;
      try (InputStream input = AgeThroughputBenchmark.class.getResourceAsStream(resource)) {
        if (input == null) throw new IOException("Missing fixture " + resource);
        bytes = input.readAllBytes();
      }
      int separator = -1;
      for (int i = 0; i + 1 < bytes.length; i++) {
        if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
          separator = i + 2;
          break;
        }
        if (i + 3 < bytes.length
            && bytes[i] == '\r'
            && bytes[i + 1] == '\n'
            && bytes[i + 2] == '\r'
            && bytes[i + 3] == '\n') {
          separator = i + 4;
          break;
        }
      }
      if (separator < 0) throw new IOException("No metadata/payload separator in " + name);
      String metadata = new String(bytes, 0, separator, StandardCharsets.ISO_8859_1);
      byte[] payload = java.util.Arrays.copyOfRange(bytes, separator, bytes.length);
      byte[] ciphertext = payload;
      if (metadata.contains("compressed: zlib")) {
        try (InputStream inflater = new InflaterInputStream(new ByteArrayInputStream(payload))) {
          ciphertext = inflater.readAllBytes();
        }
      }
      if (!metadata.contains("expect: success"))
        throw new IOException("Fixture does not expect success: " + name);
      String digest = metadataLine(metadata, "payload: ");
      int scryptWorkFactor =
          metadata.contains("passphrase: ") ? parseScryptWorkFactor(ciphertext) : 0;
      return new Fixture(
          metadata, ciphertext, digest, metadata.contains("armored: yes"), scryptWorkFactor);
    }

    private static int parseScryptWorkFactor(byte[] ciphertext) throws IOException {
      String header = new String(ciphertext, StandardCharsets.ISO_8859_1);
      java.util.regex.Matcher stanza =
          java.util.regex.Pattern.compile("(?m)^-> scrypt \\S+ (\\d+)$").matcher(header);
      if (!stanza.find()) throw new IOException("Missing scrypt stanza in passphrase fixture");
      try {
        return Integer.parseInt(stanza.group(1));
      } catch (NumberFormatException exception) {
        throw new IOException("Invalid scrypt work factor in fixture", exception);
      }
    }

    private static String metadataLine(String metadata, String prefix) throws IOException {
      for (String line : metadata.split("\\R"))
        if (line.startsWith(prefix)) return line.substring(prefix.length());
      throw new IOException("Missing " + prefix + " metadata");
    }
  }
}
