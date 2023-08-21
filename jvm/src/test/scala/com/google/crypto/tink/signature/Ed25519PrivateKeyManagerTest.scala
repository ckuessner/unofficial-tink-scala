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
package com.google.crypto.tink.signature

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.{KeyTemplate, PublicKeySign, PublicKeyVerify}
import com.google.crypto.tink.internal.KeyTypeManager
import com.google.crypto.tink.proto.{Ed25519PrivateKey, Ed25519PublicKey}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.subtle.{Ed25519Verify, Random}
import com.google.crypto.tink.testing.KeyTypeManagerTestUtil.testKeyTemplateCompatible
import com.google.crypto.tink.testing.TestUtil
import com.google.protobuf.ByteString
import org.junit.Assert.{assertEquals, assertThrows}
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.io.{ByteArrayInputStream, InputStream}
import java.security.GeneralSecurityException
import java.util

/** Unit tests for Ed25519PrivateKeyManager. */
@RunWith(classOf[JUnit4]) class Ed25519PrivateKeyManagerTest {
  final private val manager = new Ed25519PrivateKeyManager
  final private val factory = manager.keyFactory

  @Test
  @throws[Exception]
  def basics(): Unit = {
    assertThat(manager.getKeyType).isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey")
    assertThat(manager.keyMaterialType).isEqualTo(KeyMaterialType.ASYMMETRIC_PRIVATE)
  }

  //@Test
  //public void validateKeyFormat_empty() throws Exception {
  //  factory.validateKeyFormat(Ed25519KeyFormat.getDefaultInstance());
  //}
  @Test
  @throws[Exception]
  def createKey_checkValues(): Unit = {
    val privateKey = factory.createKey
    assertEquals(32, privateKey.getKeyValue.size)
    assertEquals(32, privateKey.getPublicKey.getKeyValue.size)
  }

  @Test
  @throws[Exception]
  def validateKey_empty_throws(): Unit = {
    assertThrows(classOf[GeneralSecurityException], () => manager.validateKey(Ed25519PrivateKey.getDefaultInstance))
  }

  // Tests that generated keys are different.
  @Test
  @throws[Exception]
  def createKey_differentValues(): Unit = {
    val keys = new util.TreeSet[String]
    val numTests = 100
    for (i <- 0 until numTests) {
      keys.add(TestUtil.hexEncode(factory.createKey.getKeyValue.toByteArray))
    }
    assertThat(keys).hasSize(numTests)
  }

  @Test
  @throws[Exception]
  def createKeyThenValidate(): Unit = {
    manager.validateKey(factory.createKey)
  }

  //@Test
  //public void validateKey_wrongVersion() throws Exception {
  //  Ed25519PrivateKey validKey = factory.createKey(Ed25519KeyFormat.getDefaultInstance());
  //  Ed25519PrivateKey invalidKey = Ed25519PrivateKey.newBuilder(validKey).setVersion(1).build();
  //  assertThrows(GeneralSecurityException.class, () -> manager.validateKey(invalidKey));
  //}
  @Test
  @throws[Exception]
  def validateKey_wrongLength64_throws(): Unit = {
    val validKey = factory.createKey
    val invalidKey = validKey.toBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(64))).build
    assertThrows(classOf[GeneralSecurityException], () => manager.validateKey(invalidKey))
  }

  @Test
  @throws[Exception]
  def validateKey_wrongLengthPublicKey64_throws(): Unit = {
    val invalidKey = Ed25519PrivateKey.newBuilder.setPublicKey(Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(64))).build).build
    assertThrows(classOf[GeneralSecurityException], () => manager.validateKey(invalidKey))
  }

  /** Tests that a public key is extracted properly from a private key. */
  @Test
  @throws[Exception]
  def getPublicKey_checkValues(): Unit = {
    val privateKey = factory.createKey
    val publicKey = manager.getPublicKey(privateKey)
    assertThat(publicKey).isEqualTo(privateKey.getPublicKey)
  }

  @Test
  @throws[Exception]
  def createPrimitive(): Unit = {
    val privateKey = factory.createKey
    val signer = manager.getPrimitive(privateKey, classOf[PublicKeySign])
    val verifier = new Ed25519Verify(privateKey.getPublicKey.getKeyValue.toByteArray)
    val message = Random.randBytes(135)
    verifier.verify(signer.sign(message), message)
  }

  @Test
  @throws[Exception]
  def testEd25519Template(): Unit = {
    val template = Ed25519PrivateKeyManager.ed25519Template
    assertThat(template.getTypeUrl).isEqualTo(new Ed25519PrivateKeyManager().getKeyType)
    assertThat(template.getOutputPrefixType).isEqualTo(KeyTemplate.OutputPrefixType.TINK)
  }

  @Test
  @throws[Exception]
  def testRawEd25519Template(): Unit = {
    val template = Ed25519PrivateKeyManager.rawEd25519Template
    assertThat(template.getTypeUrl).isEqualTo(new Ed25519PrivateKeyManager().getKeyType)
    assertThat(template.getOutputPrefixType).isEqualTo(KeyTemplate.OutputPrefixType.RAW)
  }

  @Test
  @throws[Exception]
  def testKeyTemplateAndManagerCompatibility(): Unit = {
    val manager = new Ed25519PrivateKeyManager
    testKeyTemplateCompatible(manager, Ed25519PrivateKeyManager.ed25519Template)
    testKeyTemplateCompatible(manager, Ed25519PrivateKeyManager.rawEd25519Template)
  }

  @Test
  @throws[Exception]
  def testDeriveKey(): Unit = {
    val keySize = 32
    val keyMaterial = Random.randBytes(100)
    val key = factory.deriveKey(new ByteArrayInputStream(keyMaterial))
    assertEquals(keySize, key.getKeyValue.size)
    for (i <- 0 until keySize) {
      assertThat(key.getKeyValue.byteAt(i)).isEqualTo(keyMaterial(i))
    }
  }

  @Test
  @throws[Exception]
  def testDeriveKey_handlesDataFragmentationCorrectly(): Unit = {
    val keySize = 32
    val randomness: Byte = 4
    val fragmentedInputStream = new InputStream() {
      override def read = 0

      override def read(b: Array[Byte], off: Int, len: Int): Int = {
        b(off) = randomness
        1
      }
    }
    val key = factory.deriveKey(fragmentedInputStream)
    assertEquals(keySize, key.getKeyValue.size)
    for (i <- 0 until keySize) {
      assertThat(key.getKeyValue.byteAt(i)).isEqualTo(randomness)
    }
  }

  @Test
  @throws[Exception]
  def testDeriveKeySignVerify(): Unit = {
    val keyMaterial = Random.randBytes(100)
    val key = factory.deriveKey(new ByteArrayInputStream(keyMaterial))
    val signer = manager.getPrimitive(key, classOf[PublicKeySign])
    val verifier = new Ed25519Verify(key.getPublicKey.getKeyValue.toByteArray)
    val message = Random.randBytes(135)
    verifier.verify(signer.sign(message), message)
  }

  @Test
  @throws[Exception]
  def testDeriveKeyNotEnoughRandomness(): Unit = {
    val keyMaterial = Random.randBytes(10)
    assertThrows(classOf[GeneralSecurityException], () => factory.deriveKey(new ByteArrayInputStream(keyMaterial)))
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