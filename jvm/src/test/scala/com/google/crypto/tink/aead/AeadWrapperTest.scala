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
package com.google.crypto.tink.aead

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.proto.Keyset.Key
import com.google.crypto.tink.proto.{KeyData, KeyStatusType, Keyset, OutputPrefixType, XChaCha20Poly1305Key}
import com.google.crypto.tink.subtle.{Bytes, Random}
import com.google.crypto.tink.testing.TestUtil
import com.google.crypto.tink.{Aead, CleartextKeysetHandle, KeysetHandle, PrimitiveSet, Registry}
import com.google.protobuf.ByteString
import org.junit.Assert.assertThrows
import org.junit.experimental.theories.{DataPoints, FromDataPoints, Theories, Theory}
import org.junit.runner.RunWith
import org.junit.{BeforeClass, Test}

import java.nio.charset.StandardCharsets.UTF_8
import java.security.GeneralSecurityException
import java.util

/** Unit tests for {@link AeadWrapper}. */
@RunWith(classOf[Theories]) object AeadWrapperTest {
  private var xChaCha20Poly1305Key: XChaCha20Poly1305Key = null
  private var xChaCha20Poly1305Key2: XChaCha20Poly1305Key = null

  @BeforeClass
  @throws[Exception]
  def setUpClass(): Unit = {
    AeadConfig.register()
    xChaCha20Poly1305Key = XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build
    xChaCha20Poly1305Key2 = XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build
  }

  @throws[Exception]
  private def getKey(xChaChaPoly1305Key: XChaCha20Poly1305Key, keyId: Int, prefixType: OutputPrefixType) =
    TestUtil.createKey(
      TestUtil.createKeyData(xChaChaPoly1305Key, "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", KeyData.KeyMaterialType.SYMMETRIC),
      keyId,
      KeyStatusType.ENABLED,
      prefixType
    )

  @DataPoints(Array("outputPrefixType"))
  def OUTPUT_PREFIX_TYPES: Array[OutputPrefixType] = Array[OutputPrefixType](
    OutputPrefixType.LEGACY, OutputPrefixType.CRUNCHY, OutputPrefixType.TINK, OutputPrefixType.RAW
  )

  @DataPoints(Array("nonRawOutputPrefixType"))
  def NON_RAW_OUTPUT_PREFIX_TYPES: Array[OutputPrefixType] = Array[OutputPrefixType](
    OutputPrefixType.LEGACY, OutputPrefixType.CRUNCHY, OutputPrefixType.TINK
  )

  //@Test
  //public void testAeadWithoutAnnotations_hasNoMonitoring() throws Exception {
  //  FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
  //  MutableMonitoringRegistry.globalInstance().clear();
  //  MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
  //  Aead aead =
  //      new AeadWrapper()
  //          .wrap(
  //              TestUtil.createPrimitiveSet(
  //                  TestUtil.createKeyset(
  //                      getKey(xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.TINK)),
  //                  Aead.class));
  //  byte[] plaintext = "plaintext".getBytes(UTF_8);
  //  byte[] associatedData = "associatedData".getBytes(UTF_8);
  //  byte[] ciphertext = aead.encrypt(plaintext, associatedData);
  //  assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext);
  //  assertThrows(
  //      GeneralSecurityException.class, () -> aead.decrypt(ciphertext, "invalid".getBytes(UTF_8)));
  //  // Without annotations, nothing gets logged.
  //  assertThat(fakeMonitoringClient.getLogEntries()).isEmpty();
  //  assertThat(fakeMonitoringClient.getLogFailureEntries()).isEmpty();
  //}
  //@Test
  //public void testAeadWithAnnotations_hasMonitoring() throws Exception {
  //  FakeMonitoringClient fakeMonitoringClient = new FakeMonitoringClient();
  //  MutableMonitoringRegistry.globalInstance().clear();
  //  MutableMonitoringRegistry.globalInstance().registerMonitoringClient(fakeMonitoringClient);
  //  Key key1 = getKey(xChaCha20Poly1305Key, /*keyId=*/ 42, OutputPrefixType.TINK);
  //  Key key2 = getKey(xChaCha20Poly1305Key, /*keyId=*/ 43, OutputPrefixType.RAW);
  //  byte[] plaintext = Random.randBytes(20);
  //  byte[] plaintext2 = Random.randBytes(30);
  //  byte[] associatedData = Random.randBytes(40);
  //  // generate ciphertext2 using key2
  //  Aead aead2 =
  //      new AeadWrapper()
  //          .wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), Aead.class));
  //  byte[] ciphertext2 = aead2.encrypt(plaintext2, associatedData);
  //  MonitoringAnnotations annotations =
  //      MonitoringAnnotations.newBuilder().add("annotation_name", "annotation_value").build();
  //  PrimitiveSet<Aead> primitives =
  //      TestUtil.createPrimitiveSetWithAnnotations(
  //          TestUtil.createKeyset(key1, key2), // key1 is the primary key
  //          annotations,
  //          Aead.class);
  //  Aead aead = new AeadWrapper().wrap(primitives);
  //  byte[] ciphertext = aead.encrypt(plaintext, associatedData);  // uses key1 to encrypt
  //  byte[] decrypted = aead.decrypt(ciphertext, associatedData);
  //  assertThat(decrypted).isEqualTo(plaintext);
  //  byte[] decrypted2 = aead.decrypt(ciphertext2, associatedData);
  //  assertThat(decrypted2).isEqualTo(plaintext2);
  //  assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));
  //  List<FakeMonitoringClient.LogEntry> logEntries = fakeMonitoringClient.getLogEntries();
  //  assertThat(logEntries).hasSize(3);
  //  FakeMonitoringClient.LogEntry encEntry = logEntries.get(0);
  //  assertThat(encEntry.getKeyId()).isEqualTo(42);
  //  assertThat(encEntry.getPrimitive()).isEqualTo("aead");
  //  assertThat(encEntry.getApi()).isEqualTo("encrypt");
  //  assertThat(encEntry.getNumBytesAsInput()).isEqualTo(plaintext.length);
  //  assertThat(encEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  //  FakeMonitoringClient.LogEntry decEntry = logEntries.get(1);
  //  assertThat(decEntry.getKeyId()).isEqualTo(42);
  //  assertThat(decEntry.getPrimitive()).isEqualTo("aead");
  //  assertThat(decEntry.getApi()).isEqualTo("decrypt");
  //  // ciphertext was encrypted with key1, which has a TINK ouput prefix. This adds a 5 bytes prefix
  //  // to the ciphertext. This prefix is not included in getNumBytesAsInput.
  //  assertThat(decEntry.getNumBytesAsInput())
  //      .isEqualTo(ciphertext.length - CryptoFormat.NON_RAW_PREFIX_SIZE);
  //  assertThat(decEntry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  //  FakeMonitoringClient.LogEntry dec2Entry = logEntries.get(2);
  //  assertThat(dec2Entry.getKeyId()).isEqualTo(43);
  //  assertThat(dec2Entry.getPrimitive()).isEqualTo("aead");
  //  assertThat(dec2Entry.getApi()).isEqualTo("decrypt");
  //  // ciphertext2 was encrypted with key2, which has a RAW ouput prefix.
  //  assertThat(dec2Entry.getNumBytesAsInput()).isEqualTo(ciphertext2.length);
  //  assertThat(dec2Entry.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  //  List<FakeMonitoringClient.LogFailureEntry> failures =
  //      fakeMonitoringClient.getLogFailureEntries();
  //  assertThat(failures).hasSize(1);
  //  FakeMonitoringClient.LogFailureEntry decFailure = failures.get(0);
  //  assertThat(decFailure.getPrimitive()).isEqualTo("aead");
  //  assertThat(decFailure.getApi()).isEqualTo("decrypt");
  //  assertThat(decFailure.getKeysetInfo().getPrimaryKeyId()).isEqualTo(42);
  //  assertThat(decFailure.getKeysetInfo().getAnnotations()).isEqualTo(annotations);
  //}
  private class AlwaysFailingAead extends Aead {
    @throws[GeneralSecurityException]
    override def encrypt(plaintext: Array[Byte], aad: Array[Byte]) = throw new GeneralSecurityException("fail")

    @throws[GeneralSecurityException]
    override def decrypt(ciphertext: Array[Byte], aad: Array[Byte]) = throw new GeneralSecurityException("fail")
  }
}

@RunWith(classOf[Theories]) class AeadWrapperTest {
  @Theory
  @throws[Exception]
  def wrappedRawEncrypt_canBeDecryptedByRawPrimitive(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val primitives = PrimitiveSet.newBuilder(classOf[Aead]).addPrimaryPrimitive(rawAead, key).build
    val wrappedAead = new AeadWrapper().wrap(primitives)
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = wrappedAead.encrypt(plaintext, associatedData)
    assertThat(rawAead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext)
  }

  @Theory
  @throws[Exception]
  def wrappedRawDecrypt_decryptsRawCiphertext(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 0x66AABBCC, OutputPrefixType.RAW)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val rawCiphertext = rawAead.encrypt(plaintext, associatedData)
    val primitives = PrimitiveSet.newBuilder(classOf[Aead]).addPrimaryPrimitive(rawAead, key).build
    val wrappedAead = new AeadWrapper().wrap(primitives)
    assertThat(wrappedAead.decrypt(rawCiphertext, associatedData)).isEqualTo(plaintext)
    val invalid = "invalid".getBytes(UTF_8)
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt(rawCiphertext, invalid))
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt(invalid, associatedData))
    val ciphertextWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), rawCiphertext)
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt(ciphertextWithTinkPrefix, associatedData))
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt("".getBytes(UTF_8), associatedData))
  }

  @Theory
  @throws[Exception]
  def wrappedNonRawEncrypt_addsPrefixToRawCiphertext(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val primitives = PrimitiveSet.newBuilder(classOf[Aead]).addPrimaryPrimitive(rawAead, key).build
    val wrappedAead = new AeadWrapper().wrap(primitives)
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = wrappedAead.encrypt(plaintext, associatedData)
    val tinkPrefix = util.Arrays.copyOf(ciphertext, 5)
    val ciphertextWithoutPrefix = util.Arrays.copyOfRange(ciphertext, 5, ciphertext.length)
    assertThat(tinkPrefix).isEqualTo(TestUtil.hexDecode("0166AABBCC"))
    assertThat(rawAead.decrypt(ciphertextWithoutPrefix, associatedData)).isEqualTo(plaintext)
  }

  @Theory
  @throws[Exception]
  def wrappedNonRawDecrypt_decryptsRawCiphertextWithPrefix(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 0x66AABBCC, OutputPrefixType.TINK)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val primitives = PrimitiveSet.newBuilder(classOf[Aead]).addPrimaryPrimitive(rawAead, key).build
    val wrappedAead = new AeadWrapper().wrap(primitives)
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val rawCiphertext = rawAead.encrypt(plaintext, associatedData)
    val rawCiphertextWithTinkPrefix = Bytes.concat(TestUtil.hexDecode("0166AABBCC"), rawCiphertext)
    assertThat(wrappedAead.decrypt(rawCiphertextWithTinkPrefix, associatedData)).isEqualTo(plaintext)
    val invalid = "invalid".getBytes(UTF_8)
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt(rawCiphertextWithTinkPrefix, invalid))
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt(invalid, associatedData))
    assertThrows(classOf[GeneralSecurityException], () => wrappedAead.decrypt("".getBytes(UTF_8), associatedData))
  }

  @Theory
  @throws[Exception]
  def encrytAndDecrypt_success(@FromDataPoints("outputPrefixType") prefix: OutputPrefixType): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, prefix)
    val aead = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = aead.encrypt(plaintext, associatedData)
    assertThat(aead.decrypt(ciphertext, associatedData)).isEqualTo(plaintext)
    val invalid = "invalid".getBytes(UTF_8)
    assertThrows(classOf[GeneralSecurityException], () => aead.decrypt(ciphertext, invalid))
    assertThrows(classOf[GeneralSecurityException], () => aead.decrypt(invalid, associatedData))
    assertThrows(classOf[GeneralSecurityException], () => aead.decrypt("".getBytes(UTF_8), associatedData))
    // decrypt with a different key should fail
    val otherKey = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key2, /*keyId=*/ 234, prefix)
    val otherAead = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(otherKey), classOf[Aead]))
    assertThrows(classOf[GeneralSecurityException], () => otherAead.decrypt(ciphertext, associatedData))
  }

  @Theory
  @throws[Exception]
  def decryptWorksIfCiphertextIsValidForAnyPrimitiveInThePrimitiveSet(@FromDataPoints("outputPrefixType") prefix1: OutputPrefixType, @FromDataPoints("outputPrefixType") prefix2: OutputPrefixType): Unit = {
    val key1 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, prefix1)
    val key2 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key2, /*keyId=*/ 234, prefix2)
    val aead1 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), classOf[Aead]))
    val aead2 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), classOf[Aead]))
    val aead12 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1, key2), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext1 = aead1.encrypt(plaintext, associatedData)
    val ciphertext2 = aead2.encrypt(plaintext, associatedData)
    assertThat(aead12.decrypt(ciphertext1, associatedData)).isEqualTo(plaintext)
    assertThat(aead12.decrypt(ciphertext2, associatedData)).isEqualTo(plaintext)
  }

  @Theory
  @throws[Exception]
  def encryptUsesPrimaryPrimitive(): Unit = {
    val key1 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.TINK)
    val key2 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key2, /*keyId=*/ 234, OutputPrefixType.TINK)
    val aead1 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), classOf[Aead]))
    val aead2 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), classOf[Aead]))
    val aead12 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(/*primary=*/ key1, key2), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = aead12.encrypt(plaintext, associatedData)
    // key1 is the primary key of aead12. Therefore, aead1 should be able to decrypt, and aead2 not.
    assertThat(aead1.decrypt(ciphertext, associatedData)).isEqualTo(plaintext)
    assertThrows(classOf[GeneralSecurityException], () => aead2.decrypt(ciphertext, associatedData))
  }

  @Theory
  @throws[Exception]
  def decryptFailsIfEncryptedWithOtherKeyEvenIfKeyIdsAreEqual(@FromDataPoints("outputPrefixType") prefix: OutputPrefixType): Unit = {
    val key1 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, prefix)
    val key2 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key2, /*keyId=*/ 123, prefix)
    val aead = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), classOf[Aead]))
    val aead2 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = aead.encrypt(plaintext, associatedData)
    assertThrows(classOf[GeneralSecurityException], () => aead2.decrypt(ciphertext, associatedData))
  }

  @Theory
  @throws[Exception]
  def nonRawKeysWithSameKeyMaterialButDifferentKeyIds_decryptFails(@FromDataPoints("nonRawOutputPrefixType") prefix: OutputPrefixType): Unit = {
    val key1 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, prefix)
    val key2 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 234, prefix)
    val aead = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), classOf[Aead]))
    val aead2 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = aead.encrypt(plaintext, associatedData)
    assertThrows(classOf[GeneralSecurityException], () => aead2.decrypt(ciphertext, associatedData))
  }

  @Theory
  @throws[Exception]
  def rawKeysWithSameKeyMaterialButDifferentKeyIds_decryptWorks(): Unit = {
    val key1 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.RAW)
    val key2 = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 234, OutputPrefixType.RAW)
    val aead = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key1), classOf[Aead]))
    val aead2 = new AeadWrapper().wrap(TestUtil.createPrimitiveSet(TestUtil.createKeyset(key2), classOf[Aead]))
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = aead.encrypt(plaintext, associatedData)
    assertThat(aead2.decrypt(ciphertext, associatedData)).isEqualTo(plaintext)
  }

  @Theory
  @throws[Exception]
  def noPrimary_decryptWorks(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.TINK)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val wrappedAead = new AeadWrapper().wrap(PrimitiveSet.newBuilder(classOf[Aead]).addPrimaryPrimitive(rawAead, key).build)
    val wrappedAeadWithoutPrimary = new AeadWrapper().wrap(PrimitiveSet.newBuilder(classOf[Aead]).addPrimitive(rawAead, key).build)
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    val ciphertext = wrappedAead.encrypt(plaintext, associatedData)
    assertThat(wrappedAeadWithoutPrimary.decrypt(ciphertext, associatedData)).isEqualTo(plaintext)
  }

  @Theory
  @throws[Exception]
  def noPrimary_encryptThrowsNullPointerException(): Unit = {
    val key = AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.TINK)
    val rawAead = Registry.getPrimitive(key.getKeyData, classOf[Aead])
    val wrappedAeadWithoutPrimary = new AeadWrapper().wrap(PrimitiveSet.newBuilder(classOf[Aead]).addPrimitive(rawAead, key).build)
    val plaintext = "plaintext".getBytes(UTF_8)
    val associatedData = "associatedData".getBytes(UTF_8)
    // This usually should not happen, since the wrapper is generated by KeysetHandle,
    // which validates the keyset. See getPrimitiveFromKeysetHandleWithoutPrimary_throws test.
    assertThrows(classOf[NullPointerException], () => wrappedAeadWithoutPrimary.encrypt(plaintext, associatedData))
  }

  @Theory
  @throws[Exception]
  def getPrimitiveFromKeysetHandleWithoutPrimary_throws(): Unit = {
    val keysetWithoutPrimary = Keyset.newBuilder.addKey(AeadWrapperTest.getKey(AeadWrapperTest.xChaCha20Poly1305Key, /*keyId=*/ 123, OutputPrefixType.TINK)).build
    val keysetHandle = CleartextKeysetHandle.fromKeyset(keysetWithoutPrimary)
    assertThrows(classOf[GeneralSecurityException], () => keysetHandle.getPrimitive(classOf[Aead]))
  }
}