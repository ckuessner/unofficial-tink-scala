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
// See the License for the specified language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package com.google.crypto.tink.testing

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.*
import com.google.crypto.tink.proto.Keyset.Key
import com.google.crypto.tink.proto.{KeyTemplate, *}
import com.google.crypto.tink.subtle.{Hex, Random}
import com.google.protobuf.ByteString
import org.junit.Assert.{assertArrayEquals, assertEquals, assertTrue}

import java.nio.ByteBuffer
import java.security.{GeneralSecurityException, NoSuchAlgorithmException}
import java.util
import javax.annotation.Nullable
import javax.crypto.Cipher

/** Test helpers. */
object TestUtil {

  /** A dummy Aead-implementation that just throws exception. */
  class DummyAead extends Aead {
    @throws[GeneralSecurityException]
    override def encrypt(plaintext: Array[Byte], aad: Array[Byte]) = throw new GeneralSecurityException("dummy")

    @throws[GeneralSecurityException]
    override def decrypt(ciphertext: Array[Byte], aad: Array[Byte]) = throw new GeneralSecurityException("dummy")
  }

  /** @return a {@code PrimitiveSet} from a {@code KeySet} */
  @throws[GeneralSecurityException]
  def createPrimitiveSet[P](keyset: Keyset, inputClass: Class[P]): PrimitiveSet[P] = createPrimitiveSetWithAnnotations(keyset, null, inputClass)

  /**
   * @return a {@code PrimitiveSet} from a {@code KeySet}
   */
  @throws[GeneralSecurityException]
  def createPrimitiveSetWithAnnotations[P](keyset: Keyset, ignored: AnyRef, inputClass: Class[P]): PrimitiveSet[P] = {
    val builder = PrimitiveSet.newBuilder(inputClass)
    for (key <- keyset.keys) {
      if (key.getStatus eq KeyStatusType.ENABLED) {
        val primitive = Registry.getPrimitive(key.getKeyData, inputClass)
        if (key.getKeyId == keyset.getPrimaryKeyId) builder.addPrimaryPrimitive(primitive, key)
        else builder.addPrimitive(primitive, key)
      }
    }
    builder.build
  }

  /** @return a {@code Keyset} from a {@code handle}. */
  def getKeyset(handle: KeysetHandle): Keyset = CleartextKeysetHandle.getKeyset(handle)

  /** @return a keyset from a list of keys. The first key is primary. */
  @throws[Exception]
  def createKeyset(primary: Keyset.Key, keys: Keyset.Key*): Keyset = {
    val builder = Keyset.newBuilder
    builder.addKey(primary).setPrimaryKeyId(primary.getKeyId)
    for (key <- keys) {
      builder.addKey(key)
    }
    builder.build
  }

  /** @return a KeyTemplate with an non-existing type url. */
  @throws[Exception]
  def createKeyTemplateWithNonExistingTypeUrl: KeyTemplate = KeyTemplate.newBuilder.setTypeUrl("does-not-exist").build

  /** @return a key with some specified properties. */
  @throws[Exception]
  def createKey(keyData: KeyData, keyId: Int, status: KeyStatusType, prefixType: OutputPrefixType): Keyset.Key = Key.newBuilder.setKeyData(keyData).setStatus(status).setKeyId(keyId).setOutputPrefixType(prefixType).build

  /** @return a {@code KeyData} from a specified key. */
  @throws[Exception]
  def createKeyData(key: KeyProto, typeUrl: String, `type`: KeyData.KeyMaterialType): KeyData =
    KeyData.newBuilder
      .setValue(key)
      .setTypeUrl(typeUrl)
      .setKeyMaterialType(`type`)
      .build

  @throws[Exception]
  def createXchaCha20Poly1305KeyData(keyValue: Array[Byte]): KeyData = createKeyData(XChaCha20Poly1305Key.apply(ByteString.copyFrom(keyValue)), "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", com.google.crypto.tink.proto.KeyData.KeyMaterialType.SYMMETRIC)

  @throws[Exception]
  def createXChaCha20Poly1305Key(keyValue: Array[Byte]): XChaCha20Poly1305Key = XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(keyValue)).build

  @throws[Exception]
  def runBasicAeadTests(aead: Aead): Unit = {
    val plaintext = Random.randBytes(20)
    val associatedData = Random.randBytes(20)
    val ciphertext = aead.encrypt(plaintext, associatedData)
    val decrypted = aead.decrypt(ciphertext, associatedData)
    assertArrayEquals(plaintext, decrypted)
  }

  /** Decodes hex string. */
  def hexDecode(hexData: String): Array[Byte] = Hex.decode(hexData)

  /** Encodes bytes to hex string. */
  def hexEncode(data: Array[Byte]): String = Hex.encode(data)

  /** @return true iff two arrays are equal. */
  def arrayEquals(a: Array[Byte], b: Array[Byte]): Boolean = {
    if (a.length != b.length) return false
    var res = 0
    for (i <- 0 until a.length) {
      res |= (a(i) ^ b(i)).toByte
    }
    res == 0
  }

  /**
   * Best-effort checks that this is Android.
   *
   * @return true if running on Android.
   */
  def isAndroid: Boolean = {
    // https://developer.android.com/reference/java/lang/System#getProperties%28%29
    "The Android Project" == System.getProperty("java.vendor")
  }

  /**
   * Check that this is running in Remote Build Execution.
   *
   * @return true if running on Remote Build Execution.
   */
  def isRemoteBuildExecution = false

  /**
   * Best-effort checks that this is running under tsan. Returns false in doubt and externally to
   * google.
   */
  def isTsan = false

  /**
   * Assertion that an exception's message contains the right message. When this fails, the
   * exception's message and the expected value will be in the failure log.
   */
  def assertExceptionContains(e: Throwable, contains: String): Unit = {
    val message = String.format("Got exception with message \"%s\", expected it to contain \"%s\".", e.getMessage, contains)
    assertTrue(message, e.getMessage.contains(contains))
  }

  /** Asserts that {@code KeyInfo} is corresponding to a key from {@code keyTemplate}. */
  @throws[Exception]
  def assertKeyInfo(keyTemplate: KeyTemplate, keyInfo: KeysetInfo.KeyInfo): Unit = {
    assert(keyInfo.getKeyId > 0)
    assertThat(keyInfo.getStatus).isEqualTo(KeyStatusType.ENABLED)
    assertThat(keyInfo.getOutputPrefixType).isEqualTo(OutputPrefixType.TINK)
    assertThat(keyInfo.getTypeUrl).isEqualTo(keyTemplate.getTypeUrl)
  }

  /**
   * Replacement for org.junit.Assert.assertEquals, since org.junit.Assert.assertEquals is quite
   * slow.
   */
  @throws[Exception]
  def assertByteArrayEquals(txt: String, expected: Array[Byte], actual: Array[Byte]): Unit = {
    assertEquals(txt + " arrays not of the same length", expected.length, actual.length)
    for (i <- 0 until expected.length) {
      if (expected(i) != actual(i)) assertEquals(txt + " difference at position:" + i, expected(i), actual(i))
    }
  }

  @throws[Exception]
  def assertByteArrayEquals(expected: Array[Byte], actual: Array[Byte]): Unit = {
    assertByteArrayEquals("", expected, actual)
  }

  /**
   * Checks whether the bytes from buffer.position() to buffer.limit() are the same bytes as
   * expected.
   */
  @throws[Exception]
  def assertByteBufferContains(txt: String, expected: Array[Byte], buffer: ByteBuffer): Unit = {
    assertEquals(txt + " unexpected number of bytes in buffer", expected.length, buffer.remaining)
    val content = new Array[Byte](buffer.remaining)
    buffer.duplicate.get(content)
    assertByteArrayEquals(txt, expected, content)
  }

  @throws[Exception]
  def assertByteBufferContains(expected: Array[Byte], buffer: ByteBuffer): Unit = {
    assertByteBufferContains("", expected, buffer)
  }

  /** Convert an array of long to an array of int. */

  /** Verifies that the given entry has the specified contents. */
  def twoCompInt(a: Array[Long]): Array[Int] = {
    val ret = new Array[Int](a.length)
    for (i <- 0 until a.length) {
      ret(i) = (a(i) - (if (a(i) > Integer.MAX_VALUE) 1L << 32
      else 0)).toInt
    }
    ret
  }

  /**
   * Generates mutations of {@code bytes}, e.g., flipping bits and truncating.
   *
   * @return a list of pairs of mutated value and mutation description.
   */
  def generateMutations(bytes: Array[Byte]): util.List[BytesMutation] = {
    val res = new util.ArrayList[BytesMutation]
    // Flip bits.
    for (i <- 0 until bytes.length) {
      for (j <- 0 until 8) {
        val modifiedBytes = util.Arrays.copyOf(bytes, bytes.length)
        modifiedBytes(i) = (modifiedBytes(i) ^ (1 << j)).toByte
        res.add(new BytesMutation(modifiedBytes, String.format("Flip bit %d of data", i)))
      }
    }
    // Truncate bytes.
    for (i <- 0 until bytes.length) {
      val modifiedBytes = util.Arrays.copyOf(bytes, i)
      res.add(new BytesMutation(modifiedBytes, String.format("Truncate upto %d bytes of data", i)))
    }
    // Append an extra byte.
    res.add(new BytesMutation(util.Arrays.copyOf(bytes, bytes.length + 1), "Append an extra zero byte"))
    res
  }

  /**
   * Uses a z test on the given byte string, expecting all bits to be uniformly set with probability
   * 1/2. Returns non ok status if the z test fails by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This counts the number of bits set and expects the number to be
   * roughly half of the length of the string. The law of large numbers suggests that we can assume
   * that the longer the string is, the more accurate that estimate becomes for a random string.
   * This test is useful to detect things like strings that are entirely zero.
   *
   * <p>Note: By itself, this is a very weak test for randomness.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  @throws[GeneralSecurityException]
  def ztestUniformString(string: Array[Byte]): Unit = {
    val minAcceptableStdDevs = 10.0
    val totalBits: Double = string.length * 8
    val expected = totalBits / 2.0
    val stddev = Math.sqrt(totalBits / 4.0)

    // This test is very limited at low string lengths. Below a certain threshold it tests nothing.
    if (expected < stddev * minAcceptableStdDevs) throw new GeneralSecurityException("Test will always succeed with strings of the given length " + string.length + ". Use more bytes.")

    var numSetBits: Long = 0
    for (b: Byte <- string) {
      var unsignedInt = toUnsignedInt(b)
      // Counting the number of bits set in byte:
      while (unsignedInt != 0) {
        numSetBits += 1
        unsignedInt = unsignedInt & (unsignedInt - 1)
      }
    }
    // Check that the number of bits is within 10 stddevs.
    if (Math.abs(numSetBits.toDouble - expected) < minAcceptableStdDevs * stddev) {
      return
    }
    throw new GeneralSecurityException("Z test for uniformly distributed variable out of bounds; " + "Actual number of set bits was " + numSetBits + " expected was " + expected + " 10 * standard deviation is 10 * " + stddev + " = " + 10.0 * stddev)
  }

  /**
   * Tests that the crosscorrelation of two strings of equal length points to independent and
   * uniformly distributed strings. Returns non ok status if the z test fails by more than 10
   * standard deviations.
   *
   * <p>With less statistics jargon: This xors two strings and then performs the ZTestUniformString
   * on the result. If the two strings are independent and uniformly distributed, the xor'ed string
   * is as well. A cross correlation test will find whether two strings overlap more or less than it
   * would be expected.
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  @throws[GeneralSecurityException]
  def ztestCrossCorrelationUniformStrings(string1: Array[Byte], string2: Array[Byte]): Unit = {
    if (string1.length != string2.length) throw new GeneralSecurityException("Strings are not of equal length")
    val crossed = new Array[Byte](string1.length)
    for (i <- 0 until string1.length) {
      crossed(i) = (string1(i) ^ string2(i)).toByte
    }
    ztestUniformString(crossed)
  }

  /**
   * Tests that the autocorrelation of a string points to the bits being independent and uniformly
   * distributed. Rotates the string in a cyclic fashion. Returns non ok status if the z test fails
   * by more than 10 standard deviations.
   *
   * <p>With less statistics jargon: This rotates the string bit by bit and performs
   * ZTestCrosscorrelationUniformStrings on each of the rotated strings and the original. This will
   * find self similarity of the input string, especially periodic self similarity. For example, it
   * is a decent test to find English text (needs about 180 characters with the current settings).
   *
   * <p>Note: Having a correlation of zero is only a necessary but not sufficient condition for
   * independence.
   *
   * @throws GeneralSecurityException if uniformity error is detected, otherwise returns normally.
   */
  @throws[GeneralSecurityException]
  def ztestAutocorrelationUniformString(string: Array[Byte]): Unit = {
    val rotated = util.Arrays.copyOf(string, string.length)

    for (i <- 1 until string.length * 8) {
      rotate(rotated)
      ztestCrossCorrelationUniformStrings(string, rotated)
    }
  }

  /** Manual implementation of Byte.toUnsignedByte. The Android JDK does not have this method. */
  private def toUnsignedInt(b: Byte) = b & 0xff

  private def rotate(string: Array[Byte]): Unit = {
    val ref = util.Arrays.copyOf(string, string.length)
    for (i <- 0 until string.length) {
      string(i) = ((toUnsignedInt(string(i)) >> 1)
                    | ((1 & toUnsignedInt(ref((if (i == 0) string.length else i) - 1))) << 7)
        ).toByte
    }
  }
}