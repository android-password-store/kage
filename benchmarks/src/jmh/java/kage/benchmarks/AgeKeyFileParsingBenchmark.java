/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.benchmarks;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kage.Age;
import kage.Identity;
import kage.Recipient;
import kage.crypto.mlkem.MlKem768X25519Identity;
import kage.crypto.x25519.X25519Identity;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class AgeKeyFileParsingBenchmark {
  private String x25519Identity;
  private String hybridIdentity;
  private String x25519Recipient;
  private String hybridRecipient;

  @Setup(Level.Trial)
  public void setup() throws IOException {
    x25519Identity = identityFromFixture("x25519");
    hybridIdentity = identityFromFixture("hybrid");
    x25519Recipient = recipientFromFixture("x25519");
    hybridRecipient = recipientFromFixture("hybrid");
  }

  @Benchmark
  public List<Identity> parseX25519Identity() {
    return Age.parseIdentities(new BufferedReader(new StringReader(x25519Identity)));
  }

  @Benchmark
  public List<Identity> parseHybridIdentity() {
    return Age.parseIdentities(new BufferedReader(new StringReader(hybridIdentity)));
  }

  @Benchmark
  public List<Recipient> parseX25519Recipient() {
    return Age.parseRecipients(new BufferedReader(new StringReader(x25519Recipient)));
  }

  @Benchmark
  public List<Recipient> parseHybridRecipient() {
    return Age.parseRecipients(new BufferedReader(new StringReader(hybridRecipient)));
  }

  private static String identityFromFixture(String name) throws IOException {
    String metadata = fixtureMetadata(name);
    StringBuilder identities = new StringBuilder();
    for (String line : metadata.split("\\R")) {
      if (line.startsWith("identity: ")) {
        if (identities.length() > 0) identities.append('\n');
        identities.append(line.substring("identity: ".length()));
      }
    }
    if (identities.length() == 0) throw new IOException("Fixture has no identity: " + name);
    return identities.toString();
  }

  private static String recipientFromFixture(String name) throws IOException {
    String metadata = fixtureMetadata(name);
    for (String line : metadata.split("\\R")) {
      if (!line.startsWith("identity: ")) continue;
      String encoded = line.substring("identity: ".length());
      if (encoded.startsWith("AGE-SECRET-KEY-PQ-")) {
        return ((MlKem768X25519Identity)
                Age.parseIdentities(new BufferedReader(new StringReader(encoded))).get(0))
            .recipient()
            .encodeToString();
      }
      return ((X25519Identity)
              Age.parseIdentities(new BufferedReader(new StringReader(encoded))).get(0))
          .recipient()
          .encodeToString();
    }
    throw new IOException("Fixture has no identity: " + name);
  }

  private static String fixtureMetadata(String name) throws IOException {
    String resource = "/CCTV/age/testdata/" + name;
    try (InputStream input = AgeKeyFileParsingBenchmark.class.getResourceAsStream(resource)) {
      if (input == null) throw new IOException("Missing fixture " + resource);
      byte[] bytes = input.readAllBytes();
      int separator = -1;
      for (int i = 0; i + 1 < bytes.length; i++) {
        if (bytes[i] == '\n' && bytes[i + 1] == '\n') {
          separator = i;
          break;
        }
        if (i + 3 < bytes.length
            && bytes[i] == '\r'
            && bytes[i + 1] == '\n'
            && bytes[i + 2] == '\r'
            && bytes[i + 3] == '\n') {
          separator = i;
          break;
        }
      }
      if (separator < 0) throw new IOException("No fixture metadata separator: " + name);
      return new String(bytes, 0, separator, StandardCharsets.ISO_8859_1);
    }
  }
}
