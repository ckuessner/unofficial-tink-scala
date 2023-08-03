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
package com.google.crypto.tink.tinkkey.internal

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.{KeyTemplate, KeyTemplates, Registry}
import com.google.crypto.tink.aead.XChaCha20Poly1305KeyManager
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager
import org.junit.Assert.{assertFalse, assertThrows, assertTrue}
import org.junit.{Before, Test}
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException

/** Tests for ProtoKey */
@RunWith(classOf[JUnit4]) final class ProtoKeyTest {
  @Before
  @throws[GeneralSecurityException]
  def setUp(): Unit = {
    XChaCha20Poly1305KeyManager.register(true)
    Ed25519PrivateKeyManager.registerPair(true)
  }

  @Test
  @throws[GeneralSecurityException]
  def testProtoKey_keyDataSYMMETRIC_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("XCHACHA20_POLY1305")
    val kd = Registry.newKeyData(kt)
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThat(pk.getProtoKey).isEqualTo(kd)
    assertThat(pk.getOutputPrefixType).isEqualTo(kt.getOutputPrefixType)
    assertTrue(pk.hasSecret)
  }

  @Test
  @throws[GeneralSecurityException]
  def testProtoKey_keyDataASYMMETRICPRIVATE_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.newKeyData(kt)
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThat(pk.getProtoKey).isEqualTo(kd)
    assertThat(pk.getOutputPrefixType).isEqualTo(kt.getOutputPrefixType)
    assertTrue(pk.hasSecret)
  }

  @Test
  @throws[GeneralSecurityException]
  def testProtoKey_keyDataUNKNOWN_shouldHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.newKeyData(kt).toBuilder.setKeyMaterialType(KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL).build
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThat(pk.getProtoKey).isEqualTo(kd)
    assertThat(pk.getOutputPrefixType).isEqualTo(kt.getOutputPrefixType)
    assertTrue(pk.hasSecret)
  }

  @Test
  @throws[GeneralSecurityException]
  def testProtoKey_keyDataASYMMETRICPUBLIC_shouldNotHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.getPublicKeyData(kt.getTypeUrl, Registry.newKeyData(kt).getValue)
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThat(pk.getProtoKey).isEqualTo(kd)
    assertThat(pk.getOutputPrefixType).isEqualTo(kt.getOutputPrefixType)
    assertFalse(pk.hasSecret)
  }

  @Test
  @throws[GeneralSecurityException]
  def testProtoKey_keyDataREMOTE_shouldNotHaveSecret(): Unit = {
    val kt = KeyTemplates.get("ED25519")
    val kd = Registry.newKeyData(kt).toBuilder.setKeyMaterialType(KeyData.KeyMaterialType.REMOTE).build
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThat(pk.getProtoKey).isEqualTo(kd)
    assertThat(pk.getOutputPrefixType).isEqualTo(kt.getOutputPrefixType)
    assertFalse(pk.hasSecret)
  }

  @Test
  @throws[GeneralSecurityException]
  def testGetKeyTemplate_shouldThrow(): Unit = {
    val kt = XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template
    val kd = Registry.newKeyData(kt)
    val pk = new ProtoKey(kd, kt.getOutputPrefixType)
    assertThrows(classOf[UnsupportedOperationException], () => pk.getKeyTemplate())
  }
}