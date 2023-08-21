// Copyright 2023 Google LLC
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
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.internal.KeyTester
import com.google.crypto.tink.util.{Bytes, SecretBytes}
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException

@RunWith(classOf[JUnit4]) final class XChaCha20Poly1305KeyTest {
  @Test
  @throws[Exception]
  def buildNoPrefixVariantAndGetProperties(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    val key = XChaCha20Poly1305Key.create(keyBytes)
    assertThat(key.getParameters).isEqualTo(XChaCha20Poly1305Parameters.create)
    assertThat(key.getKeyBytes).isEqualTo(keyBytes)
    assertThat(key.getOutputPrefix).isEqualTo(Bytes.copyFrom(Array.empty[Byte]))
    assertThat(key.getIdRequirementOrNull).isNull()
  }

  @Test
  @throws[Exception]
  def buildNoPrefixVariantExplicitAndGetProperties(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, null)
    assertThat(key.getParameters).isEqualTo(XChaCha20Poly1305Parameters.create)
    assertThat(key.getKeyBytes).isEqualTo(keyBytes)
    assertThat(key.getOutputPrefix).isEqualTo(Bytes.copyFrom(Array.empty[Byte]))
    assertThat(key.getIdRequirementOrNull).isNull()
  }

  @Test
  @throws[Exception]
  def buildTinkVariantAndGetProperties(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 0x0708090a)
    assertThat(key.getParameters).isEqualTo(XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK))
    assertThat(key.getKeyBytes).isEqualTo(keyBytes)
    assertThat(key.getOutputPrefix).isEqualTo(Bytes.copyFrom(Array[Byte](0x01, 0x07, 0x08, 0x09, 0x0a)))
    assertThat(key.getIdRequirementOrNull).isEqualTo(0x708090a)
  }

  @Test
  @throws[Exception]
  def buildCrunchyVariantAndGetProperties(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, 0x0708090a)
    assertThat(key.getParameters).isEqualTo(XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY))
    assertThat(key.getKeyBytes).isEqualTo(keyBytes)
    assertThat(key.getOutputPrefix).isEqualTo(Bytes.copyFrom(Array[Byte](0x00, 0x07, 0x08, 0x09, 0x0a)))
    assertThat(key.getIdRequirementOrNull).isEqualTo(0x708090a)
  }

  @Test
  @throws[Exception]
  def wrongIdRequirement_throws(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    assertThrows(classOf[GeneralSecurityException], () => XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, 1115))
    assertThrows(classOf[GeneralSecurityException], () => XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, null))
    assertThrows(classOf[GeneralSecurityException], () => XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, keyBytes, null))
  }

  @Test
  @throws[Exception]
  def testEqualities(): Unit = {
    val keyBytes = SecretBytes.randomBytes(32)
    val keyBytesCopy = SecretBytes.copyFrom(keyBytes.toByteArray(InsecureSecretKeyAccess.get), InsecureSecretKeyAccess.get)
    val keyBytesDiff = SecretBytes.randomBytes(32)
    new KeyTester().addEqualityGroup("No prefix, keyBytes", XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, null), XChaCha20Poly1305Key.create(keyBytes), XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytesCopy, null)).addEqualityGroup("No prefix, different key bytes", XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytesDiff, null)).addEqualityGroup("Tink with key id 1907, keyBytes32", XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 1907), XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, keyBytesCopy, 1907)).addEqualityGroup("Tink with key id 1908, keyBytes32", XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 1908)).addEqualityGroup("Crunchy with key id 1907, keyBytes32", XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, 1907)).doTests()
  }
}