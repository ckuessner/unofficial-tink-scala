// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.signature;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.proto.Ed25519PrivateKey;
import com.google.crypto.tink.proto.Ed25519PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Ed25519Verify;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Ed25519PrivateKeyManager. */
@RunWith(JUnit4.class)
public class Ed25519PrivateKeyManagerTest {
  private final Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();
  private final KeyTypeManager.KeyFactory<Ed25519PrivateKey> factory =
      manager.keyFactory();

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType())
        .isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey");
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE);
  }

  //@Test
  //public void validateKeyFormat_empty() throws Exception {
  //  factory.validateKeyFormat(Ed25519KeyFormat.getDefaultInstance());
  //}

  @Test
  public void createKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey();
    assertEquals(32, privateKey.getKeyValue().size());
    assertEquals(32, privateKey.getPublicKey().getKeyValue().size());
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> manager.validateKey(Ed25519PrivateKey.getDefaultInstance()));
  }

  // Tests that generated keys are different.
  @Test
  public void createKey_differentValues() throws Exception {
    Set<String> keys = new TreeSet<>();
    int numTests = 100;
    for (int i = 0; i < numTests; i++) {
      keys.add(TestUtil.hexEncode(factory.createKey().getKeyValue().toByteArray()));
    }
    assertThat(keys).hasSize(numTests);
  }

  @Test
  public void createKeyThenValidate() throws Exception {
    manager.validateKey(factory.createKey());
  }

  //@Test
  //public void validateKey_wrongVersion() throws Exception {
  //  Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
  //  Ed25519PrivateKey invalidKey = Ed25519PrivateKey.newBuilder(validKey).setVersion(1).build();
  //  assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  //}

  @Test
  public void validateKey_wrongLength64_throws() throws Exception {
    Ed25519PrivateKey validKey = factory.createKey();
    Ed25519PrivateKey invalidKey =
        validKey.toBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(64)))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  }

  @Test
  public void validateKey_wrongLengthPublicKey64_throws() throws Exception {
    Ed25519PrivateKey invalidKey =
        Ed25519PrivateKey.newBuilder()
            .setPublicKey(
                Ed25519PublicKey.newBuilder()
                    .setKeyValue(ByteString.copyFrom(Random.randBytes(64))).build())
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  public void getPublicKey_checkValues() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey();
    Ed25519PublicKey publicKey = manager.getPublicKey(privateKey);
    assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
  }

  @Test
  public void createPrimitive() throws Exception {
    Ed25519PrivateKey privateKey = factory.createKey();
    PublicKeySign signer = manager.getPrimitive(privateKey, PublicKeySign.class);

    PublicKeyVerify verifier =
        new Ed25519Verify(privateKey.getPublicKey().getKeyValue().toByteArray());
    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void testEd25519Template() throws Exception {
    KeyTemplate template = Ed25519PrivateKeyManager.ed25519Template();
    assertThat(template.getTypeUrl()).isEqualTo(new Ed25519PrivateKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.TINK);
  }

  @Test
  public void testRawEd25519Template() throws Exception {
    KeyTemplate template = Ed25519PrivateKeyManager.rawEd25519Template();
    assertThat(template.getTypeUrl()).isEqualTo(new Ed25519PrivateKeyManager().getKeyType());
    assertThat(template.getOutputPrefixType()).isEqualTo(KeyTemplate.OutputPrefixType.RAW);
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Ed25519PrivateKeyManager manager = new Ed25519PrivateKeyManager();

    testKeyTemplateCompatible(manager, Ed25519PrivateKeyManager.ed25519Template());
    testKeyTemplateCompatible(manager, Ed25519PrivateKeyManager.rawEd25519Template());
  }

  @Test
  public void testDeriveKey() throws Exception {
    final int keySize = 32;
    byte[] keyMaterial = Random.randBytes(100);
    Ed25519PrivateKey key =
        factory.deriveKey(new ByteArrayInputStream(keyMaterial));
    assertEquals(keySize, key.getKeyValue().size());
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(keyMaterial[i]);
    }
  }

  @Test
  public void testDeriveKey_handlesDataFragmentationCorrectly() throws Exception {
    int keySize = 32;
    byte randomness = 4;
    InputStream fragmentedInputStream =
        new InputStream() {
          @Override
          public int read() {
            return 0;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            b[off] = randomness;
            return 1;
          }
        };

    Ed25519PrivateKey key = factory.deriveKey(fragmentedInputStream);

    assertEquals(keySize, key.getKeyValue().size());
    for (int i = 0; i < keySize; ++i) {
      assertThat(key.getKeyValue().byteAt(i)).isEqualTo(randomness);
    }
  }

  @Test
  public void testDeriveKeySignVerify() throws Exception {
    byte[] keyMaterial = Random.randBytes(100);
    Ed25519PrivateKey key =
        factory.deriveKey(
            new ByteArrayInputStream(keyMaterial));

    PublicKeySign signer = manager.getPrimitive(key, PublicKeySign.class);
    PublicKeyVerify verifier = new Ed25519Verify(key.getPublicKey().getKeyValue().toByteArray());
    byte[] message = Random.randBytes(135);
    verifier.verify(signer.sign(message), message);
  }

  @Test
  public void testDeriveKeyNotEnoughRandomness() throws Exception {
    byte[] keyMaterial = Random.randBytes(10);
    assertThrows(GeneralSecurityException.class, () -> factory.deriveKey(
          new ByteArrayInputStream(keyMaterial)));
  }

  //@Test
  //public void testDeriveKeyWrongVersion() throws Exception {
  //  byte[] keyMaterial = Random.randBytes(32);
  //  assertThrows(GeneralSecurityException.class, () -> factory.deriveKey(
  //        Ed25519KeyFormat.newBuilder().setVersion(1).build(),
  //        new ByteArrayInputStream(keyMaterial)));
  //}

  //@Test
  //public void testKeyFormats() throws Exception {
  //  factory.validateKeyFormat(factory.keyFormats().get("ED25519").keyFormat);
  //  factory.validateKeyFormat(factory.keyFormats().get("ED25519_RAW").keyFormat);
  //  factory.validateKeyFormat(factory.keyFormats().get("ED25519WithRawOutput").keyFormat);
  //}
}
