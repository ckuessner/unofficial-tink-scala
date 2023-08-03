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

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.proto.{KeyStatusType, OutputPrefixType}
import com.google.crypto.tink.testing.TestUtil
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.nio.charset.StandardCharsets.UTF_8

/** Tests for CryptoFormat. */
@RunWith(classOf[JUnit4]) class CryptoFormatTest {
  @throws[Exception]
  private def getKey(`type`: OutputPrefixType, keyId: Int) = TestUtil.createKey(TestUtil.createXchaCha20Poly1305KeyData("01234567890123456789012345678901".getBytes(UTF_8)), keyId, KeyStatusType.ENABLED, `type`)

  @Test
  @throws[Exception]
  def testRawPrefix(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 0x66AABBCC))).isEmpty()
  }

  @Test
  @throws[Exception]
  def testTinkPrefix(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 0x66AABBCC))).isEqualTo(TestUtil.hexDecode("0166AABBCC"))
  }

  @Test
  @throws[Exception]
  def testLegacyPrefix(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 0x66AABBCC))).isEqualTo(TestUtil.hexDecode("0066AABBCC"))
  }

  @Test
  @throws[Exception]
  def testCrunchyPrefix(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 0x66AABBCC))).isEqualTo(TestUtil.hexDecode("0066AABBCC"))
  }

  @Test
  @throws[Exception]
  def testConstants(): Unit = {
    assertThat(CryptoFormat.NON_RAW_PREFIX_SIZE).isEqualTo(5)
    assertThat(CryptoFormat.LEGACY_PREFIX_SIZE).isEqualTo(5)
    assertThat(CryptoFormat.TINK_PREFIX_SIZE).isEqualTo(5)
    assertThat(CryptoFormat.RAW_PREFIX_SIZE).isEqualTo(0)
    assertThat(CryptoFormat.RAW_PREFIX).isEmpty()
    assertThat(CryptoFormat.TINK_START_BYTE).isEqualTo(1)
    assertThat(CryptoFormat.LEGACY_START_BYTE).isEqualTo(0)
  }

  @Test
  @throws[Exception]
  def testConstantsAreConsistentWithGetOutputPrefix(): Unit = {
    val tinkPrefix = CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 42))
    assertThat(tinkPrefix).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE)
    assertThat(tinkPrefix).hasLength(CryptoFormat.TINK_PREFIX_SIZE)
    assertThat(tinkPrefix(0)).isEqualTo(CryptoFormat.TINK_START_BYTE)
    val legacyPrefix = CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 42))
    assertThat(legacyPrefix).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE)
    assertThat(legacyPrefix).hasLength(CryptoFormat.LEGACY_PREFIX_SIZE)
    assertThat(legacyPrefix(0)).isEqualTo(CryptoFormat.LEGACY_START_BYTE)
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 42))).hasLength(CryptoFormat.NON_RAW_PREFIX_SIZE)
  }

  @Test
  @throws[Exception]
  def testKeyIdWithMsbSet(): Unit = {
    val keyId = 0xFF7F1058
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, keyId))).isEqualTo(TestUtil.hexDecode("01FF7F1058"))
  }

  @Test
  @throws[Exception]
  def testKeyIdIsZero(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 0))).isEmpty()
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 0))).isEqualTo(TestUtil.hexDecode("0100000000"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 0))).isEqualTo(TestUtil.hexDecode("0000000000"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 0))).isEqualTo(TestUtil.hexDecode("0000000000"))
  }

  @Test
  @throws[Exception]
  def testKeyIdIsMinusOne(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, -1))).isEmpty()
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, -1))).isEqualTo(TestUtil.hexDecode("01FFFFFFFF"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, -1))).isEqualTo(TestUtil.hexDecode("00FFFFFFFF"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, -1))).isEqualTo(TestUtil.hexDecode("00FFFFFFFF"))
  }

  @Test
  @throws[Exception]
  def testKeyIdIsMaxInt(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, 2147483647))).isEmpty()
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, 2147483647))).isEqualTo(TestUtil.hexDecode("017FFFFFFF"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, 2147483647))).isEqualTo(TestUtil.hexDecode("007FFFFFFF"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, 2147483647))).isEqualTo(TestUtil.hexDecode("007FFFFFFF"))
  }

  @Test
  @throws[Exception]
  def testKeyIdIsMinInt(): Unit = {
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.RAW, -2147483648))).isEmpty()
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.TINK, -2147483648))).isEqualTo(TestUtil.hexDecode("0180000000"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.LEGACY, -2147483648))).isEqualTo(TestUtil.hexDecode("0080000000"))
    assertThat(CryptoFormat.getOutputPrefix(getKey(OutputPrefixType.CRUNCHY, -2147483648))).isEqualTo(TestUtil.hexDecode("0080000000"))
  }
}