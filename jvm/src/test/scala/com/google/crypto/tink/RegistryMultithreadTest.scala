// Copyright 2022 Google LLC
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
import com.google.crypto.tink.proto.*
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.protobuf.ByteString
import org.junit.Assert.{assertNotNull, assertTrue}
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException
import java.util
import java.util.concurrent.TimeUnit.SECONDS
import java.util.concurrent.{ExecutorService, Executors, Future}

/** Thread safety tests for {@link Registry}. */
@RunWith(classOf[JUnit4]) object RegistryMultithreadTest {
  private class Primitive {}

  private class TestKeyManager(private val typeUrl: String) extends KeyManager[RegistryMultithreadTest.Primitive] {
    //@Override
    //public Primitive getPrimitive(ByteString proto) throws GeneralSecurityException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
    @throws[GeneralSecurityException]
    override def getPrimitive(proto: KeyProto) = throw new UnsupportedOperationException("Not needed for test")

    //@Override
    //public MessageLite newKey(ByteString template) throws GeneralSecurityException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
    @throws[GeneralSecurityException]
    override def newKey = throw new UnsupportedOperationException("Not needed for test")

    @throws[GeneralSecurityException]
    override def newKeyData = throw new UnsupportedOperationException("Not needed for test")

    override def doesSupport(typeUrl: String) = throw new UnsupportedOperationException("Not needed for test")

    override def getKeyType: String = this.typeUrl

    override def getPrimitiveClass: Class[RegistryMultithreadTest.Primitive] = classOf[RegistryMultithreadTest.Primitive]
  }

  private class TestKeyTypeManager(private val typeUrl: String) extends KeyTypeManager[XChaCha20Poly1305Key](classOf[XChaCha20Poly1305Key]) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType = throw new UnsupportedOperationException("Not needed for test")

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: XChaCha20Poly1305Key): Unit = {
    }
    //@Override
    //public XChaCha20Poly1305Key parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
  }

  private class TestPublicKeyTypeManager(private val typeUrl: String) extends KeyTypeManager[Ed25519PublicKey](classOf[Ed25519PublicKey]) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType = throw new UnsupportedOperationException("Not needed for test")

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PublicKey): Unit = {
    }
    //@Override
    //public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
  }

  private class TestPrivateKeyTypeManager(private val typeUrl: String) extends PrivateKeyTypeManager[Ed25519PrivateKey, Ed25519PublicKey](classOf[Ed25519PrivateKey], classOf[Ed25519PublicKey]) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType = throw new UnsupportedOperationException("Not needed for test")

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PrivateKey): Unit = {
    }

    //@Override
    //public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
    override def getPublicKey(privateKey: Ed25519PrivateKey) = throw new UnsupportedOperationException("Not needed for test")
  }

  private val REPETITIONS = 1000
}

@RunWith(classOf[JUnit4]) final class RegistryMultithreadTest {
  @Test
  @throws[Exception]
  def registerAndGetKeyManager_works(): Unit = {
    val threadPool = Executors.newFixedThreadPool(4)
    val futures = new util.ArrayList[Future[_]]
    Registry.registerKeyManager(new RegistryMultithreadTest.TestKeyManager("KeyManagerStart"), false)
    //Registry.registerKeyManager(new TestKeyTypeManager("KeyTypeManagerStart"), false);
    //Registry.registerAsymmetricKeyManagers(
    //    new TestPrivateKeyTypeManager("PrivateKeyTypeManagerStart"),
    //    new TestPublicKeyTypeManager("PublicKeyTypeManagerStart"),
    //    false);
    futures.add(threadPool.submit(new Runnable() {
      override def run(): Unit = {
        try for (i <- 0 until RegistryMultithreadTest.REPETITIONS) {
          Registry.registerKeyManager(new RegistryMultithreadTest.TestKeyManager("KeyManager" + i), false)
        }
        catch {
          case e: GeneralSecurityException =>
            throw new RuntimeException(e)
        }
      }
    }))
    //futures.add(
    //    threadPool.submit(
    //        () -> {
    //          try {
    //            for (int i = 0; i < REPETITIONS; ++i) {
    //              Registry.registerKeyManager(new TestKeyTypeManager("KeyTypeManager" + i), false);
    //            }
    //          } catch (GeneralSecurityException e) {
    //            throw new RuntimeException(e);
    //          }
    //        }));
    //futures.add(
    //    threadPool.submit(
    //        () -> {
    //          try {
    //            for (int i = 0; i < REPETITIONS; ++i) {
    //              Registry.registerAsymmetricKeyManagers(
    //                  new TestPrivateKeyTypeManager("Private" + i),
    //                  new TestPublicKeyTypeManager("Public" + i),
    //                  false);
    //            }
    //          } catch (GeneralSecurityException e) {
    //            throw new RuntimeException(e);
    //          }
    //        }));
    futures.add(threadPool.submit(new Runnable() {
      override def run(): Unit = {
        try for (i <- 0 until RegistryMultithreadTest.REPETITIONS) {
          assertNotNull(Registry.getKeyManager("KeyManagerStart"))
        }
        catch {
          case e: GeneralSecurityException =>
            throw new RuntimeException(e)
        }
      }
    }))
    threadPool.shutdown()
    assertTrue(threadPool.awaitTermination(300, SECONDS))
    for (i <- 0 until futures.size) {
      futures.get(i).get // This will throw an exception if the thread threw an exception.
    }
  }
  // TODO(tholenst): Epxand the test coverage for primitive wrappers and catalogues.
}