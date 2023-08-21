// Copyright 2020 Google LLC
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
package com.google.crypto.tink.tinkkey

import com.google.common.truth.Expect
import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.KeyTemplate.OutputPrefixType
import com.google.crypto.tink.aead.XChaCha20Poly1305KeyManager
import com.google.crypto.tink.proto.{KeyData, XChaCha20Poly1305Key}
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.google.crypto.tink.tinkkey.internal.ProtoKey
import com.google.crypto.tink.{KeyTemplate, KeyTemplates, Registry}
import com.google.errorprone.annotations.Immutable
import com.google.protobuf.ByteString
import org.junit.Assert.{assertFalse, assertThrows, assertTrue}
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.junit.{Assert, Before, Rule, Test}

import java.security.GeneralSecurityException
import java.util

/** Tests for KeyHandle * */
@RunWith(classOf[JUnit4])
object KeyHandleTest {
  @Immutable
  final private[tinkkey] class DummyTinkKey extends TinkKey {
    final private var _hasSecret = false
    final private var template: KeyTemplate = null

    def this(hasSecret: Boolean) = {
      this()
      this._hasSecret = hasSecret
      this.template = null
    }

    def this(hasSecret: Boolean, template: KeyTemplate) = {
      this()
      this._hasSecret = hasSecret
      this.template = template
    }

    override def hasSecret: Boolean = _hasSecret

    override def getKeyTemplate: KeyTemplate = {
      if (template == null) throw new UnsupportedOperationException
      template
    }
  }
}

@RunWith(classOf[JUnit4])
final class KeyHandleTest {
  private val _expect = Expect.create
  @Rule
  def expect: Expect = _expect

  @Before
  @throws[Exception]
  def setUp(): Unit = {
    XChaCha20Poly1305KeyManager.register(/* newKeyAllowed= */ true)
    Ed25519PrivateKeyManager.registerPair(/* newKeyAllowed= */ true)
  }

  @Test
  @throws[Exception]
  def createFromKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ true)
    val access = KeyAccess.publicAccess
    assertThrows(classOf[GeneralSecurityException], () => KeyHandle.createFromKey(key, access))
  }

  @Test
  @throws[Exception]
  def createFromKey_keyDataSymmetric_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("XCHACHA20_POLY1305")
    val kd = Registry.newKeyData(kt)
    val kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType)
    assertTrue(kh.hasSecret)
  }

  @Test
  @throws[Exception]
  def createFromKey_keyDataAsymmetricPrivate_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.newKeyData(kt)
    val kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType)
    assertTrue(kh.hasSecret)
  }

  @Test
  @throws[Exception]
  def createFromKey_keyDataUnknown_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.newKeyData(kt).toBuilder.setKeyMaterialType(KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL).build
    val kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType)
    assertTrue(kh.hasSecret)
  }

  @Test
  @throws[Exception]
  def createFromKey_keyDataAsymmetricPublic_shouldNotHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.getPublicKeyData(kt.getTypeUrl, Registry.newKeyData(kt).getValue)
    val kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType)
    assertFalse(kh.hasSecret)
  }

  //@Test
  //public void createFromKey_keyDataRemote_shouldNotHaveSecret() throws Exception {
  //  KeyTemplate kt = KeyTemplates.get("ED25519");
  //  KeyData kd =
  //      KeyData.newBuilder()
  //          .mergeFrom(Registry.newKeyData(kt))
  //          .setKeyMaterialType(KeyData.KeyMaterialType.REMOTE)
  //          .build();
  //  KeyHandle kh = KeyHandle.createFromKey(kd, kt.getOutputPrefixType());
  //  assertThat(kh.hasSecret()).isFalse();
  //}
  @Test
  @throws[Exception]
  def generateNew_shouldWork(): Unit = {
    val template = KeyTemplates.get("XCHACHA20_POLY1305")
    val handle = KeyHandle.generateNew(template)
    val protoKey = handle.getKey(SecretKeyAccess.insecureSecretAccess).asInstanceOf[ProtoKey]
    expect.that(protoKey.getOutputPrefixType).isEqualTo(KeyTemplate.OutputPrefixType.TINK)
    expect.that(protoKey.hasSecret).isEqualTo(true)
    val keyData = protoKey.getProtoKey
    expect.that(keyData.getTypeUrl).isEqualTo(template.getTypeUrl)
    //AesEaxKeyFormat aesEaxKeyFormat =
    //    AesEaxKeyFormat.parseFrom(template.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    //AesEaxKey aesEaxKey =
    //    AesEaxKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    //expect.that(aesEaxKey.getKeyValue().size()).isEqualTo(aesEaxKeyFormat.getKeySize());
  }

  //@Test
  //public void generateNew_compareWith_createFromKeyViaProtoKey_shouldBeEqual() throws Exception {
  //  KeyTemplate template = KeyTemplates.get("AES128_EAX");
  //  KeyData keyData = Registry.newKeyData(template);
  //  ProtoKey protoKey = new ProtoKey(keyData, template.getOutputPrefixType());
  //  KeyHandle handle1 = KeyHandle.generateNew(template);
  //  KeyHandle handle2 = KeyHandle.createFromKey(protoKey, SecretKeyAccess.insecureSecretAccess());
  //  expect.that(handle1.getStatus()).isEqualTo(handle2.getStatus());
  //  ProtoKey outputProtoKey1 = (ProtoKey) handle1.getKey(SecretKeyAccess.insecureSecretAccess());
  //  ProtoKey outputProtoKey2 = (ProtoKey) handle2.getKey(SecretKeyAccess.insecureSecretAccess());
  //  expect
  //      .that(outputProtoKey1.getOutputPrefixType())
  //      .isEqualTo(outputProtoKey2.getOutputPrefixType());
  //  expect.that(handle1.hasSecret()).isEqualTo(handle2.hasSecret());
  //}
  //@Test
  //public void generateNew_generatesDifferentKeys() throws Exception {
  //  KeyTemplate template = KeyTemplates.get("AES128_EAX");
  //  Set<String> keys = new TreeSet<>();
  //  int numKeys = 2;
  //  for (int j = 0; j < numKeys; j++) {
  //    KeyHandle handle = KeyHandle.generateNew(template);
  //    ProtoKey protoKey = (ProtoKey) handle.getKey(SecretKeyAccess.insecureSecretAccess());
  //    KeyData keyData = protoKey.getProtoKey();
  //    AesEaxKey aesEaxKey =
  //        AesEaxKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
  //    keys.add(aesEaxKey.getKeyValue().toStringUtf8());
  //  }
  //  assertThat(keys).hasSize(numKeys);
  //}
  @Test
  @throws[Exception]
  def generateNew_unregisteredTypeUrl_shouldThrow(): Unit = {
    val typeUrl = "testNewKeyDataTypeUrl"
    val keyTemplate = com.google.crypto.tink.KeyTemplate.create(typeUrl, OutputPrefixType.TINK)
    assertThrows(classOf[GeneralSecurityException], () => KeyHandle.generateNew(keyTemplate))
  }

  @Test
  @throws[Exception]
  def hasSecret_tinkKeyWithSecret_shouldReturnTrue(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ true)
    val kh = KeyHandle.createFromKey(key, SecretKeyAccess.insecureSecretAccess)
    assertTrue(kh.hasSecret)
  }

  @Test
  @throws[Exception]
  def hasSecret_tinkKeyWithoutSecret_shouldReturnFalse(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ false)
    val access = KeyAccess.publicAccess
    val kh = KeyHandle.createFromKey(key, access)
    assertFalse(kh.hasSecret)
  }

  @Test
  @throws[Exception]
  def getKey_tinkKeyWithoutSecret_noSecretKeyAccess_shouldWork(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ false)
    val access = KeyAccess.publicAccess
    val kh = KeyHandle.createFromKey(key, access)
    assertThat(kh.getKey(access)).isEqualTo(key)
  }

  @Test
  @throws[Exception]
  def getKey_tinkKeyWithoutSecret_secretKeyAccess_shouldWork(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ false)
    val access = SecretKeyAccess.insecureSecretAccess
    val kh = KeyHandle.createFromKey(key, access)
    assertThat(kh.getKey(access)).isEqualTo(key)
  }

  @Test
  @throws[Exception]
  def getKey_tinkKeyWithSecret_noSecretKeyAccess_shouldThrowException(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ true)
    val kh = KeyHandle.createFromKey(key, SecretKeyAccess.insecureSecretAccess)
    val pubAccess = KeyAccess.publicAccess
    assertThrows(classOf[GeneralSecurityException], () => kh.getKey(pubAccess))
  }

  @Test
  @throws[Exception]
  def getKey_tinkKeyWithSecret_secretKeyAccess_shouldWork(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ true)
    val access = SecretKeyAccess.insecureSecretAccess
    val kh = KeyHandle.createFromKey(key, access)
    assertThat(kh.getKey(access)).isEqualTo(key)
  }

  @Test
  @throws[Exception]
  def getKeyTemplate(): Unit = {
    val keyTemplate = KeyTemplates.get("ED25519_RAW")
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ false, keyTemplate)
    val keyHandle = KeyHandle.createFromKey(key, KeyAccess.publicAccess)
    val returnedKeyTemplate = keyHandle.getKeyTemplate
    assertThat(returnedKeyTemplate).isEqualTo(keyTemplate)
  }

  @Test
  @throws[Exception]
  def getKeyTemplate_tinkKeyWithoutKeyTemplateSupport_shouldThrow(): Unit = {
    val key = new KeyHandleTest.DummyTinkKey(/* hasSecret= */ false)
    val keyHandle = KeyHandle.createFromKey(key, KeyAccess.publicAccess)
    assertThrows(classOf[UnsupportedOperationException], () => keyHandle.getKeyTemplate)
  }
}