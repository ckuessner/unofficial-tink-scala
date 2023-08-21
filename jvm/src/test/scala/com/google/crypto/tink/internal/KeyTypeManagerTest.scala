// Copyright 2019 Google LLC
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
package com.google.crypto.tink.internal

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{KeyData, XChaCha20Poly1305Key}
import com.google.protobuf.ByteString
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.io.InputStream
import java.security.GeneralSecurityException

/** Tests for KeyTypeManager. */
@RunWith(classOf[JUnit4]) object KeyTypeManagerTest {
  private val TEST_BYTESTRING = ByteString.copyFromUtf8("Some text")

  /**
   * A KeyTypeManager for testing. It accepts XChaCha20Poly1305Keys and produces primitives as with the passed
   * in factory.
   */
  class TestKeyTypeManager(factories: PrimitiveFactory[_, XChaCha20Poly1305Key]*) extends KeyTypeManager[XChaCha20Poly1305Key](classOf[XChaCha20Poly1305Key], factories:_*) {
    override def getKeyType = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"

    override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.SYMMETRIC

    override def validateKey(keyProto: XChaCha20Poly1305Key): Unit = {
    }
    //@Override
    //public XChaCha20Poly1305Key parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return XChaCha20Poly1305Key.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
  }

  final private class Primitive1(private val keyValue: ByteString) {
    def getKeyValue: ByteString = keyValue
  }

  final private class Primitive2(private val size: Int) {
    def getSize: Int = size
  }
}

@RunWith(classOf[JUnit4]) final class KeyTypeManagerTest {
  @Test
  @throws[Exception]
  def getPrimitive_works(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager(new PrimitiveFactory[KeyTypeManagerTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive1]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive1(key.getKeyValue)
    }, new PrimitiveFactory[KeyTypeManagerTest.Primitive2, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive2]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive2(key.getKeyValue.size)
    })
    val primitive1 = keyManager.getPrimitive(XChaCha20Poly1305Key.newBuilder.setKeyValue(KeyTypeManagerTest.TEST_BYTESTRING).build, classOf[KeyTypeManagerTest.Primitive1])
    assertThat(primitive1.getKeyValue).isEqualTo(KeyTypeManagerTest.TEST_BYTESTRING)
    val primitive2 = keyManager.getPrimitive(XChaCha20Poly1305Key.newBuilder.setKeyValue(KeyTypeManagerTest.TEST_BYTESTRING).build, classOf[KeyTypeManagerTest.Primitive2])
    assertThat(primitive2.getSize).isEqualTo(KeyTypeManagerTest.TEST_BYTESTRING.size)
  }

  @Test
  @throws[Exception]
  def firstSupportedPrimitiveClass(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager(new PrimitiveFactory[KeyTypeManagerTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive1]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive1(key.getKeyValue)
    }, new PrimitiveFactory[KeyTypeManagerTest.Primitive2, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive2]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive2(key.getKeyValue.size)
    })
    assertThat(keyManager.firstSupportedPrimitiveClass).isEqualTo(classOf[KeyTypeManagerTest.Primitive1])
  }

  @Test
  @throws[Exception]
  def firstSupportedPrimitiveClass_returnsVoid(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager
    assertThat(keyManager.firstSupportedPrimitiveClass).isEqualTo(classOf[Void])
  }

  @Test
  @throws[Exception]
  def supportedPrimitives_equalsGivenPrimitives(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager(new PrimitiveFactory[KeyTypeManagerTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive1]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive1(key.getKeyValue)
    }, new PrimitiveFactory[KeyTypeManagerTest.Primitive2, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive2]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive2(key.getKeyValue.size)
    })
    assertThat(keyManager.supportedPrimitives).isEqualTo(Set(classOf[KeyTypeManagerTest.Primitive1], classOf[KeyTypeManagerTest.Primitive2]))
  }

  @Test
  @throws[Exception]
  def supportedPrimitives_canBeEmpty(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager
    assert(keyManager.supportedPrimitives.isEmpty)
  }

  @Test
  @throws[Exception]
  def getPrimitive_throwsForUnknownPrimitives(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager
    assertThrows(classOf[IllegalArgumentException], () => keyManager.getPrimitive(XChaCha20Poly1305Key.getDefaultInstance, classOf[KeyTypeManagerTest.Primitive1]))
  }

  @Test
  @throws[Exception]
  def getPrimitive_throwsForVoid(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager
    assertThrows(classOf[IllegalArgumentException], () => keyManager.getPrimitive(XChaCha20Poly1305Key.getDefaultInstance, classOf[Void]))
  }

  @Test
  @throws[Exception]
  def keyFactory_throwsUnsupported(): Unit = {
    val keyManager = new KeyTypeManagerTest.TestKeyTypeManager
    assertThrows(classOf[UnsupportedOperationException], () => keyManager.keyFactory)
  }

  @Test
  @throws[Exception]
  def constructor_repeatedPrimitive_throwsIllegalArgument(): Unit = {
    assertThrows(classOf[IllegalArgumentException], () => new KeyTypeManagerTest.TestKeyTypeManager(new PrimitiveFactory[KeyTypeManagerTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive1]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive1(key.getKeyValue)
    }, new PrimitiveFactory[KeyTypeManagerTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyTypeManagerTest.Primitive1]) {
      override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyTypeManagerTest.Primitive1(key.getKeyValue)
    }))
  }

  @Test
  @throws[Exception]
  def readNBytes_works(): Unit = {
    val randomness: Byte = 4
    val fragmentedInputStream = new InputStream() {
      override def read = 0

      override def read(b: Array[Byte], off: Int, len: Int): Int = {
        b(off) = randomness
        1
      }
    }
    val readBytes = new Array[Byte](4)
    KeyTypeManager.KeyFactory.readFully(fragmentedInputStream, readBytes)
    assertThat(readBytes).isEqualTo(Array[Byte](4, 4, 4, 4))
  }

  @Test
  @throws[Exception]
  def readNBytes_throwsOnNotEnoughPseudorandomness(): Unit = {
    val randomness: Byte = 4
    val shortInputStream = new InputStream() {
      private[internal] var numReads = 3

      override def read = 0

      override def read(b: Array[Byte], off: Int, len: Int): Int = {
        if (numReads == 0) return -1
        numReads -= 1
        b(off) = randomness
        1
      }
    }
    val readBytes = new Array[Byte](4)
    assertThrows(classOf[GeneralSecurityException], () => KeyTypeManager.KeyFactory.readFully(shortInputStream, readBytes))
  }
}