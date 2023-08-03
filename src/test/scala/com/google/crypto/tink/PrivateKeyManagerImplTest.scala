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
package com.google.crypto.tink

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.internal.{KeyTypeManager, PrivateKeyTypeManager}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{Ed25519PrivateKey, Ed25519PublicKey, KeyData}
import com.google.crypto.tink.subtle.Random
import com.google.crypto.tink.testing.TestUtil.assertExceptionContains
import com.google.protobuf.ByteString
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException
import scala.collection.Seq
import scala.collection.immutable.List$

/** Tests the methods implemented in KeyManagerImpl using the concrete implementation above. */
@RunWith(classOf[JUnit4]) object PrivateKeyManagerImplTest {
  private class TestPublicKeyTypeManager extends KeyTypeManager[Ed25519PublicKey](classOf[Ed25519PublicKey]) {
    override def getKeyType = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"

    override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PUBLIC

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PublicKey): Unit = {
      if (keyProto.getKeyValue.size != 32) throw new GeneralSecurityException("validateKey(Ed25519PublicKey) failed")
    }
    //@Override
    //public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
  }

  private class TestPrivateKeyTypeManager extends PrivateKeyTypeManager[Ed25519PrivateKey, Ed25519PublicKey](classOf[Ed25519PrivateKey], classOf[Ed25519PublicKey]) {
    override def getKeyType = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"

    override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PRIVATE

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PrivateKey): Unit = {
      // Throw by hand so we can verify the exception comes from here.
      if (keyProto.getKeyValue.size != 32) throw new GeneralSecurityException("validateKey(Ed25519PrivateKey) failed")
    }

    //@Override
    //public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
    override def getPublicKey(privateKey: Ed25519PrivateKey): Ed25519PublicKey = privateKey.getPublicKey
  }
}

@RunWith(classOf[JUnit4]) final class PrivateKeyManagerImplTest {
  @Test
  @throws[Exception]
  def getPublicKeyData_works(): Unit = {
    val privateManager = new PrivateKeyManagerImplTest.TestPrivateKeyTypeManager
    val publicManager = new PrivateKeyManagerImplTest.TestPublicKeyTypeManager
    val manager = new PrivateKeyManagerImpl[Void, Ed25519PrivateKey, Ed25519PublicKey](privateManager, publicManager, classOf[Void])
    val privateKey = Ed25519PrivateKey
      .newBuilder
      .setPublicKey(Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build)
      .setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build
    val keyData = manager.getPublicKeyData(privateKey)
    assertThat(keyData.getTypeUrl).isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PublicKey")
    //Ed25519PublicKey publicKey =
    //    Ed25519PublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    //assertThat(publicKey).isEqualTo(privateKey.getPublicKey());
    //assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  @throws[Exception]
  def getPublicKeyData_invalidPrivateKey_throws(): Unit = {
    val privateManager = new PrivateKeyManagerImplTest.TestPrivateKeyTypeManager
    val publicManager = new PrivateKeyManagerImplTest.TestPublicKeyTypeManager
    val manager = new PrivateKeyManagerImpl[Void, Ed25519PrivateKey, Ed25519PublicKey](privateManager, publicManager, classOf[Void])
    val privateKey = Ed25519PrivateKey
      .newBuilder
      .setPublicKey(Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build)
      .setKeyValue(ByteString.copyFrom(Random.randBytes(33))).build
    val e = assertThrows(classOf[GeneralSecurityException], () => manager.getPublicKeyData(privateKey))
    assertExceptionContains(e, "validateKey(Ed25519PrivateKey)")
  }

  @Test
  @throws[Exception]
  def getPublicKeyData_invalidPublicKey_throws(): Unit = {
    val privateManager = new PrivateKeyManagerImplTest.TestPrivateKeyTypeManager
    val publicManager = new PrivateKeyManagerImplTest.TestPublicKeyTypeManager
    val manager = new PrivateKeyManagerImpl[Void, Ed25519PrivateKey, Ed25519PublicKey](privateManager, publicManager, classOf[Void])
    val privateKey = Ed25519PrivateKey
      .newBuilder
      .setPublicKey(Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(33))).build)
      .setKeyValue(ByteString.copyFrom(Random.randBytes(32))).build
    val e = assertThrows(classOf[GeneralSecurityException], () => manager.getPublicKeyData(privateKey))
    assertExceptionContains(e, "validateKey(Ed25519PublicKey)")
  }
}