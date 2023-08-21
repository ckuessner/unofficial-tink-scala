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
import com.google.crypto.tink.internal.{KeyTypeManager, PrimitiveFactory, PrivateKeyTypeManager}
import com.google.crypto.tink.proto.*
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.protobuf.ByteString
import org.junit.Assert.{assertFalse, assertThrows, assertTrue}
import org.junit.Assume.{assumeFalse, assumeTrue}
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException

/** Tests for {@link KeyManagerRegistry}. */
@RunWith(classOf[JUnit4]) object KeyManagerRegistryTest {
  private class Primitive1 {}

  private class Primitive2 {}

  private class TestKeyManager(private val typeUrl: String) extends KeyManager[KeyManagerRegistryTest.Primitive1] {
    @throws[GeneralSecurityException]
    override def getPrimitive(proto: KeyProto) = throw new UnsupportedOperationException("Not needed for test")

    //@Override
    //public Primitive1 getPrimitive() throws GeneralSecurityException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
    @throws[GeneralSecurityException]
    override def newKey = throw new UnsupportedOperationException("Not needed for test")

    //@Override
    //public MessageLite newKey(MessageLite template) throws GeneralSecurityException {
    //  throw new UnsupportedOperationException("Not needed for test");
    //}
    @throws[GeneralSecurityException]
    override def newKeyData = throw new UnsupportedOperationException("Not needed for test")

    override def doesSupport(typeUrl: String) = throw new UnsupportedOperationException("Not needed for test")

    override def getKeyType: String = this.typeUrl

    override def getPrimitiveClass: Class[KeyManagerRegistryTest.Primitive1] = classOf[KeyManagerRegistryTest.Primitive1]
  }

  private class TestKeyTypeManager(private val typeUrl: String) extends KeyTypeManager[XChaCha20Poly1305Key](classOf[XChaCha20Poly1305Key], new PrimitiveFactory[KeyManagerRegistryTest.Primitive1, XChaCha20Poly1305Key](classOf[KeyManagerRegistryTest.Primitive1]) {
    override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyManagerRegistryTest.Primitive1
  }, new PrimitiveFactory[KeyManagerRegistryTest.Primitive2, XChaCha20Poly1305Key](classOf[KeyManagerRegistryTest.Primitive2]) {
    override def getPrimitive(key: XChaCha20Poly1305Key) = new KeyManagerRegistryTest.Primitive2
  }) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType = throw new UnsupportedOperationException("Not needed for test")

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: XChaCha20Poly1305Key): Unit = {
    }
    //@Override
    //public XChaCha20Poly1305Key parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return XChaCha20Poly1305Key.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
    ///* We set the key manager FIPS compatible per default, such that all tests which use key
    // * managers can also be run if Tink.useOnlyFips() == true.*/
    //@Override
    //public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    //  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    //}
  }

  //// The method "parseKeyData" only works if a KeyTypeManager was registered -- KeyManager objects
  //// do not support this.
  //@Test
  //public void testParseKeyData_keyTypeManager_works() throws Exception {
  //  //if (TinkFipsUtil.useOnlyFips()) {
  //  //  assumeTrue(
  //  //      "If FIPS is required, we can only register managers if the fips module is available",
  //  //      TinkFipsUtil.fipsModuleAvailable());
  //  //}
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  registry.registerKeyManager(new TestKeyTypeManager("typeUrl"));
  //  XChaCha20Poly1305Key key = XChaCha20Poly1305Key.newBuilder().build();
  //  KeyData keyData =
  //      KeyData.newBuilder()
  //          .setTypeUrl("typeUrl")
  //          .setValue(key)
  //          .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
  //          .build();
  //  assertThat(registry.parseKeyData(keyData)).isEqualTo(key);
  //}
  //@Test
  //public void testParseKeyData_keyManager_returnsNull() throws Exception {
  //  //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  registry.registerKeyManager(new TestKeyManager("typeUrl"));
  //  XChaCha20Poly1305Key key = XChaCha20Poly1305Key.newBuilder().build();
  //  KeyData keyData =
  //      KeyData.newBuilder()
  //          .setTypeUrl("typeUrl")
  //          .setValue(key)
  //          .setKeyMaterialType(KeyMaterialType.SYMMETRIC)
  //          .build();
  //  assertThat(registry.parseKeyData(keyData)).isNull();
  //}
  private class TestPublicKeyTypeManager(private val typeUrl: String) extends KeyTypeManager[Ed25519PublicKey](classOf[Ed25519PublicKey]) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PUBLIC

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PublicKey): Unit = {

      // The point of registering both key managers at once is that when we get the public key
      // from the privateKeyManager, the registry validates the key proto here. We check this call
      // happens by throwing here.
    }
    //@Override
    //public Ed25519PublicKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return Ed25519PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
    ///* We set the key manager FIPS compatible per default, such that all tests which use key
    // * managers can also be run if Tink.useOnlyFips() == true.*/
    //@Override
    //public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    //  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    //}
  }

  private class TestPrivateKeyTypeManager(private val typeUrl: String) extends PrivateKeyTypeManager[Ed25519PrivateKey, Ed25519PublicKey](classOf[Ed25519PrivateKey], classOf[Ed25519PublicKey]) {
    override def getKeyType: String = typeUrl

    override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PRIVATE

    @throws[GeneralSecurityException]
    override def validateKey(keyProto: Ed25519PrivateKey): Unit = {
    }

    //@Override
    //public Ed25519PrivateKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    //  return Ed25519PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
    //}
    override def getPublicKey(privateKey: Ed25519PrivateKey): Ed25519PublicKey = privateKey.getPublicKey
    ///* We set the key manager FIPS compatible per default, such that all tests which use key
    // * managers can also be run if Tink.useOnlyFips() == true.*/
    //@Override
    //public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    //  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    //}
  }
}

@RunWith(classOf[JUnit4]) final class KeyManagerRegistryTest {
  @Test
  @throws[Exception]
  def testEmptyRegistry(): Unit = {
    val registry = new KeyManagerRegistry
    assertThrows(classOf[GeneralSecurityException], () => registry.getKeyManager("customTypeUrl", classOf[Aead]))
    assertThrows(classOf[GeneralSecurityException], () => registry.getKeyManager("customTypeUrl"))
    assertThrows(classOf[GeneralSecurityException], () => registry.getUntypedKeyManager("customTypeUrl"))
    assertFalse(registry.typeUrlExists("customTypeUrl"))
  }

  @Test
  @throws[Exception]
  def testRegisterKeyManager_works(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    val manager = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl")
    registry.registerKeyManager(manager)
    assertThat(registry.getKeyManager("customTypeUrl", classOf[KeyManagerRegistryTest.Primitive1])).isSameInstanceAs(manager)
    assertTrue(registry.typeUrlExists("customTypeUrl"))
  }

  @Test
  @throws[Exception]
  def testRegisterKeyManager_twice_works(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    val manager1 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl")
    val manager2 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl")
    registry.registerKeyManager(manager1)
    registry.registerKeyManager(manager2)
    assertThat(registry.getKeyManager("customTypeUrl", classOf[KeyManagerRegistryTest.Primitive1])).isAnyOf(manager1, manager2)
  }

  @Test
  @throws[Exception]
  def testRegisterKeyManager_differentManagersSameKeyType_fails(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    registry.registerKeyManager(new KeyManagerRegistryTest.TestKeyManager("customTypeUrl"))
    // Adding {} at the end makes this an anonymous subclass, hence a different class, so this
    // throws.
    assertThrows(classOf[GeneralSecurityException], () => registry.registerKeyManager(new KeyManagerRegistryTest.TestKeyManager("customTypeUrl") {}))
  }

  @Test
  @throws[Exception]
  def testRegisterKeyManager_twoKeyTypes_works(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    val manager1 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl1")
    val manager2 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl2")
    registry.registerKeyManager(manager1)
    registry.registerKeyManager(manager2)
    assertThat(registry.getKeyManager("customTypeUrl1", classOf[KeyManagerRegistryTest.Primitive1])).isSameInstanceAs(manager1)
    assertThat(registry.getKeyManager("customTypeUrl2", classOf[KeyManagerRegistryTest.Primitive1])).isSameInstanceAs(manager2)
  }

  @Test
  @throws[Exception]
  def testRegisterKeyTypeManager_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val manager = new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1")
    assertThrows(classOf[GeneralSecurityException], () => registry.getUntypedKeyManager("customTypeUrl1"))
    registry.registerKeyManager(manager)
    assertThat(registry.getUntypedKeyManager("customTypeUrl1")).isNotNull()
  }

  @Test
  @throws[Exception]
  def testRegisterKeyTypeManager_twice_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val manager1 = new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1")
    val manager2 = new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1")
    registry.registerKeyManager(manager1)
    registry.registerKeyManager(manager2)
  }

  @Test
  @throws[Exception]
  def testRegisterKeyManagerAndKeyTypeManager_fails(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    // After a registered KeyTypeManager, the KeyManager registering fails.
    val registry = new KeyManagerRegistry
    registry.registerKeyManager(new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1"))
    assertThrows(classOf[GeneralSecurityException], () => registry.registerKeyManager(new KeyManagerRegistryTest.TestKeyManager("customTypeUrl1")))
    // After a registered KeyManager, the KeyTypeManager registering fails.
    val registry2 = new KeyManagerRegistry
    registry2.registerKeyManager(new KeyManagerRegistryTest.TestKeyManager("customTypeUrl1"))
    assertThrows(classOf[GeneralSecurityException], () => registry2.registerKeyManager(new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1")))
  }

  @Test
  @throws[Exception]
  def testTypeUrlExists(): Unit = {
    //assumeFalse("Unable to test with KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    val manager1 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl1")
    val manager2 = new KeyManagerRegistryTest.TestKeyManager("customTypeUrl2")
    registry.registerKeyManager(manager1)
    registry.registerKeyManager(manager2)
    assertTrue(registry.typeUrlExists("customTypeUrl1"))
    assertTrue(registry.typeUrlExists("customTypeUrl2"))
    assertFalse(registry.typeUrlExists("unknownTypeUrl"))
  }

  @Test
  @throws[Exception]
  def testTypeUrlExists_keyTypeManagers(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val manager1 = new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl1")
    val manager2 = new KeyManagerRegistryTest.TestKeyTypeManager("customTypeUrl2")
    registry.registerKeyManager(manager1)
    registry.registerKeyManager(manager2)
    assertTrue(registry.typeUrlExists("customTypeUrl1"))
    assertTrue(registry.typeUrlExists("customTypeUrl2"))
    assertFalse(registry.typeUrlExists("unknownTypeUrl"))
  }

  @Test
  @throws[Exception]
  def testGetKeyManager_works(): Unit = {
    //assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    val registry = new KeyManagerRegistry
    val registered = new KeyManagerRegistryTest.TestKeyManager("typeUrl")
    registry.registerKeyManager(registered)
    val aeadManager1 = registry.getKeyManager("typeUrl", classOf[KeyManagerRegistryTest.Primitive1])
    val aeadManager2 = registry.getKeyManager("typeUrl")
    val manager = registry.getUntypedKeyManager("typeUrl")
    assertThat(aeadManager1).isSameInstanceAs(registered)
    assertThat(aeadManager2).isSameInstanceAs(registered)
    assertThat(manager).isSameInstanceAs(registered)
  }

  @Test
  @throws[Exception]
  def testRegisterAsymmetricKeyManager_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl"))
    assertThat(registry.getUntypedKeyManager("privateTypeUrl")).isNotNull()
    assertThat(registry.getUntypedKeyManager("publicTypeUrl")).isNotNull()
  }

  @Test
  @throws[Exception]
  def testRegisterAsymmetricKeyManagerTwice_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl"))
    registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl"))
    assertThat(registry.getUntypedKeyManager("privateTypeUrl")).isNotNull()
    assertThat(registry.getUntypedKeyManager("publicTypeUrl")).isNotNull()
  }

  @Test
  @throws[Exception]
  def testRegisterDifferentAsymmetricKeyManagerForTheSameKeyTypeUrl_throws(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl"))
    assertThrows(classOf[GeneralSecurityException], () => registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl") {}, new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl")))
    assertThrows(classOf[GeneralSecurityException], () => registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl") {}))
  }

  @Test
  @throws[Exception]
  def testRegisterAsymmetricKeyManager_thenSymmetricDifferentType_throws(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    registry.registerAsymmetricKeyManagers(new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl"), new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl"))
    assertThrows(classOf[GeneralSecurityException], () => registry.registerKeyManager(new KeyManagerRegistryTest.TestKeyTypeManager("privateTypeUrl")))
  }

  @Test
  @throws[Exception]
  def testAsymmetricKeyManagers_getPublicKey_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val privateKeyTypeManager = new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl")
    val publicKeyTypeManager = new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl")
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager)
    val publicKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Array[Byte](0, 1, 2, 3))).build
    val privateKey = Ed25519PrivateKey.newBuilder.setPublicKey(publicKey).build
    val publicKeyData = registry.getUntypedKeyManager("privateTypeUrl").asInstanceOf[PrivateKeyManager[_]].getPublicKeyData(privateKey)
    //Ed25519PublicKey parsedPublicKey =
    //    Ed25519PublicKey.parseFrom(
    //        publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    //assertThat(parsedPublicKey).isEqualTo(publicKey);
  }

  ///**
  // * The point of registering Asymmetric KeyManagers together is that the public key validation
  // * method is invoked when we get a public key from a private key. Here we verify that this
  // * happens.
  // */
  //@Test
  //public void testAsymmetricKeyManagers_getPublicKey_validationIsInvoked_throws() throws Exception {
  //  if (TinkFipsUtil.useOnlyFips()) {
  //    assumeTrue(
  //        "If FIPS is required, we can only register managers if the fips module is available",
  //        TinkFipsUtil.fipsModuleAvailable());
  //  }
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  TestPrivateKeyTypeManager privateKeyTypeManager =
  //      new TestPrivateKeyTypeManager("privateTypeUrl");
  //  TestPublicKeyTypeManager publicKeyTypeManager = new TestPublicKeyTypeManager("publicTypeUrl");
  //  registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager);
  //  // Version 0 will make sure that we get a validation error thrown
  //  Ed25519PublicKey publicKey = Ed25519PublicKey.newBuilder().setVersion(0).build();
  //  ByteString serializedPrivateKey =
  //      Ed25519PrivateKey.newBuilder().setPublicKey(publicKey).setVersion(1).build().toByteString();
  //  PrivateKeyManager<?> privateKeyManager =
  //      (PrivateKeyManager) registry.getUntypedKeyManager("privateTypeUrl");
  //  GeneralSecurityException thrown =
  //      assertThrows(
  //          GeneralSecurityException.class,
  //          () -> privateKeyManager.getPublicKeyData(serializedPrivateKey));
  //  assertThat(thrown).hasMessageThat().contains("PublicKeyManagerValidationIsInvoked");
  //}
  @Test
  @throws[Exception]
  def testAsymmetricKeyManagers_doubleRegistration_classChange_throws(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val privateKeyTypeManager = new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl")
    val publicKeyTypeManager1 = new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl")
    // Add parentheses to make sure it's a different class which implements the manager.
    val publicKeyTypeManager2 = new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl") {}
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager1)
    assertThrows(classOf[GeneralSecurityException], () => registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager2))
  }

  /** One is allowed to sometimes register asymmetric key managers without their counterpart. */
  @Test
  @throws[Exception]
  def testAsymmetricKeyManagers_registerOnceWithThenWithout_works(): Unit = {
    //if (TinkFipsUtil.useOnlyFips()) {
    //  assumeTrue(
    //      "If FIPS is required, we can only register managers if the fips module is available",
    //      TinkFipsUtil.fipsModuleAvailable());
    //}
    val registry = new KeyManagerRegistry
    val privateKeyTypeManager = new KeyManagerRegistryTest.TestPrivateKeyTypeManager("privateTypeUrl")
    val publicKeyTypeManager = new KeyManagerRegistryTest.TestPublicKeyTypeManager("publicTypeUrl")
    registry.registerKeyManager(privateKeyTypeManager)
    registry.registerKeyManager(publicKeyTypeManager)
    registry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager)
    registry.registerKeyManager(privateKeyTypeManager)
    registry.registerKeyManager(publicKeyTypeManager)
    // If one ever registers the two together, we keep that one, so one can get public keys:
    val publicKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Array[Byte](0, 1, 2, 3))).build
    val privateKey = Ed25519PrivateKey.newBuilder.setPublicKey(publicKey).build
    val publicKeyData = registry.getUntypedKeyManager("privateTypeUrl").asInstanceOf[PrivateKeyManager[_]].getPublicKeyData(privateKey)
    //Ed25519PublicKey parsedPublicKey =
    //    Ed25519PublicKey.parseFrom(
    //        publicKeyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    //assertThat(parsedPublicKey).isEqualTo(publicKey);
  }
  //@Test
  //public void testFips_registerNonFipsKeyTypeManagerFails() throws Exception {
  //  //assumeTrue(TinkFipsUtil.fipsModuleAvailable());
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  Registry.restrictToFipsIfEmpty();
  //  assertThrows(
  //      GeneralSecurityException.class,
  //      () ->
  //          registry.registerKeyManager(
  //              new TestKeyTypeManager("typeUrl") {
  //                @Override
  //                public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
  //                  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
  //                }
  //              }));
  //}
  //@Test
  //public void testFips_registerFipsKeyTypeManagerSucceeds() throws Exception {
  //  assumeTrue(TinkFipsUtil.fipsModuleAvailable());
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  Registry.restrictToFipsIfEmpty();
  //  registry.registerKeyManager(new TestKeyTypeManager("typeUrl"));
  //}
  //@Test
  //public void testFips_registerNonFipsKeyTypeManagerAsymmetricFails() throws Exception {
  //  assumeTrue(TinkFipsUtil.fipsModuleAvailable());
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  Registry.restrictToFipsIfEmpty();
  //  assertThrows(
  //      GeneralSecurityException.class,
  //      () ->
  //          registry.registerAsymmetricKeyManagers(
  //              new TestPrivateKeyTypeManager("privateTypeUrl") {
  //                @Override
  //                public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
  //                  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
  //                }
  //              },
  //              new TestPublicKeyTypeManager("publicTypeUrl")));
  //  assertThrows(
  //      GeneralSecurityException.class,
  //      () ->
  //          registry.registerAsymmetricKeyManagers(
  //              new TestPrivateKeyTypeManager("privateTypeUrl"),
  //              new TestPublicKeyTypeManager("publicTypeUrl") {
  //                @Override
  //                public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
  //                  return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
  //                }
  //              }));
  //}
  //@Test
  //public void testFips_registerFipsKeyTypeManagerAsymmetric_works() throws Exception {
  //  assumeTrue(TinkFipsUtil.fipsModuleAvailable());
  //  KeyManagerRegistry registry = new KeyManagerRegistry();
  //  Registry.restrictToFipsIfEmpty();
  //  registry.registerAsymmetricKeyManagers(
  //      new TestPrivateKeyTypeManager("privateTypeUrl"),
  //      new TestPublicKeyTypeManager("publicTypeUrl"));
  //}
}