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
package com.google.crypto.tink

import com.google.crypto.tink.proto.{KeyData, KeyStatusType, Keyset, OutputPrefixType}
import com.google.crypto.tink.testing.TestUtil
import com.google.crypto.tink.testing.TestUtil.assertExceptionContains
import org.junit.Assert.{assertThrows, fail}
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException


// TODO(b/74251398): add tests for other functions.

/** Tests for Util. */
@RunWith(classOf[JUnit4]) class UtilTest {
  @Test
  @throws[Exception]
  def testValidateKeyset_shouldWork(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    val keyset = TestUtil.createKeyset(TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), -42, KeyStatusType.ENABLED, OutputPrefixType.TINK))
    try Util.validateKeyset(keyset)
    catch {
      case e: GeneralSecurityException =>
        fail("Valid keyset; should not throw Exception: " + e)
    }
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_emptyKeyset_shouldFail(): Unit = {
    val e = assertThrows(classOf[GeneralSecurityException], () => Util.validateKeyset(Keyset.newBuilder.build))
    assertExceptionContains(e, "keyset must contain at least one ENABLED key")
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_multiplePrimaryKeys_shouldFail(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    // Multiple primary keys.
    val invalidKeyset = TestUtil.createKeyset(TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK), TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK))
    val e = assertThrows(classOf[GeneralSecurityException], () => Util.validateKeyset(invalidKeyset))
    assertExceptionContains(e, "keyset contains multiple primary keys")
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_primaryKeyIsDisabled_shouldFail(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    // Primary key is disabled.
    val invalidKeyset = TestUtil.createKeyset(TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.DISABLED, OutputPrefixType.TINK), TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 43, KeyStatusType.ENABLED, OutputPrefixType.TINK))
    val e = assertThrows(classOf[GeneralSecurityException], () => Util.validateKeyset(invalidKeyset))
    assertExceptionContains(e, "keyset doesn't contain a valid primary key")
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_noEnabledKey_shouldFail(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    // No ENABLED key.
    val invalidKeyset = TestUtil.createKeyset(TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.DISABLED, OutputPrefixType.TINK), TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.DESTROYED, OutputPrefixType.TINK))
    val e = assertThrows(classOf[GeneralSecurityException], () => Util.validateKeyset(invalidKeyset))
    assertExceptionContains(e, "keyset must contain at least one ENABLED key")
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_noPrimaryKey_shouldFail(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    // No primary key.
    val invalidKeyset = Keyset.newBuilder.addKey(Keyset.Key.newBuilder.setKeyData(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8"))).setKeyId(1).setStatus(KeyStatusType.ENABLED).setOutputPrefixType(OutputPrefixType.TINK).build).build
    val e = assertThrows(classOf[GeneralSecurityException], () => Util.validateKeyset(invalidKeyset))
    assertExceptionContains(e, "keyset doesn't contain a valid primary key")
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_noPrimaryKey_keysetContainsOnlyPublicKeys_shouldWork(): Unit = {
    // No primary key, but contains only public key material.
    val validKeyset = Keyset.newBuilder.addKey(Keyset.Key.newBuilder.setKeyData(TestUtil.createKeyData(KeyData.newBuilder.build.getValue, "typeUrl", KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)).setKeyId(1).setStatus(KeyStatusType.ENABLED).setOutputPrefixType(OutputPrefixType.TINK).build).build
    try Util.validateKeyset(validKeyset)
    catch {
      case e: GeneralSecurityException =>
        fail("Valid keyset, should not fail: " + e)
    }
  }

  @Test
  @throws[Exception]
  def testValidateKeyset_withDestroyedKey_shouldWork(): Unit = {
    val keyValue = "01234567890123456789012345678901"
    val validKeyset = TestUtil.createKeyset(TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.ENABLED, OutputPrefixType.TINK), TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData(keyValue.getBytes("UTF-8")), 42, KeyStatusType.DESTROYED, OutputPrefixType.TINK))
    try Util.validateKeyset(validKeyset)
    catch {
      case e: GeneralSecurityException =>
        fail("Valid keyset, should not fail: " + e)
    }
  }

  ///** Tests that getKeysetInfo doesn't contain key material. */
  //@Test
  //public void testGetKeysetInfo() throws Exception {
  //  String keyValue = "01234567890123456";
  //  Keyset keyset =
  //      TestUtil.createKeyset(
  //          TestUtil.createKey(
  //              TestUtil.createHmacKeyData(keyValue.getBytes("UTF-8"), 16),
  //              42,
  //              KeyStatusType.ENABLED,
  //              OutputPrefixType.TINK));
  //  assertTrue(keyset.toString().contains(keyValue));
  //  KeysetInfo keysetInfo = Util.getKeysetInfo(keyset);
  //  assertFalse(keysetInfo.toString().contains(keyValue));
  //}
  @Test
  @throws[Exception]
  def testAssertExceptionContains(): Unit = {
    assertExceptionContains(new GeneralSecurityException("abc"), "abc")
    try assertExceptionContains(new GeneralSecurityException("abc"), "def")
    catch {
      case e: AssertionError =>
        assertExceptionContains(e, "Got exception with message \"abc\", expected it to contain \"def\".")
    }
  }
}