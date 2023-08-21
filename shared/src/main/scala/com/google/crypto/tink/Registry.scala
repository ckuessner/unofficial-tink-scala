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

import com.google.crypto.tink.internal.{KeyTypeManager, MutablePrimitiveRegistry, PrivateKeyTypeManager}
import com.google.crypto.tink.proto.*

import java.security.GeneralSecurityException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.ConcurrentMapHasAsScala

/**
 * A global container of key managers and catalogues.
 *
 * <p>Registry maps each supported key type to a corresponding {@link KeyManager} object, which
 * "understands" the key type (i.e., the KeyManager can instantiate the primitive corresponding to
 * given key, or can generate new keys of the supported key type). It holds also a {@link
 * PrimitiveWrapper} for each supported primitive, so that it can wrap a set of primitives
 * (corresponding to a keyset) into a single primitive.
 *
 * <p>Keeping KeyManagers for all primitives in a single Registry (rather than having a separate
 * KeyManager per primitive) enables modular construction of compound primitives from "simple" ones,
 * e.g., AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
 *
 * <p>Registry is initialized at startup, and is later used to instantiate primitives for given keys
 * or keysets. Note that regular users will usually not work directly with Registry, but rather via
 * {@link TinkConfig} and {@link KeysetHandle# getPrimitive ( Class )}-methods, which in the background
 * register and query the Registry for specific KeyManagers and PrimitiveWrappers. Registry is
 * public though, to enable configurations with custom catalogues, primitives or KeyManagers.
 *
 * <p>To initialize the Registry with all key managers:
 *
 * <pre>{@code
 * TinkConfig.register();
 * }</pre>
 *
 * <p>Here's how to register only {@link Aead} key managers:
 *
 * <pre>{@code
 * AeadConfig.register();
 * }</pre>
 *
 * <p>After the Registry has been initialized, one can use get a primitive as follows:
 *
 * <pre>{@code
 * KeysetHandle keysetHandle = ...;
 * Aead aead = keysetHandle.getPrimitive(Aead.class);
 * }</pre>
 *
 * @since 1.0.0
 */
object Registry {
  private val keyManagerRegistry = new AtomicReference[KeyManagerRegistry](new KeyManagerRegistry)
  private val newKeyAllowedMap = new ConcurrentHashMap[String, Boolean].asScala // typeUrl -> newKeyAllowed mapping

  /**
   * Resets the registry.
   *
   * <p>After reset the registry is empty, i.e. it contains no key managers. Thus one might need to
   * call {@code XyzConfig.register()} to re-install the catalogues.
   *
   * <p>This method is intended for testing.
   */
  private[tink] def reset(): Unit = {
    keyManagerRegistry.set(new KeyManagerRegistry)
    MutablePrimitiveRegistry.resetGlobalInstanceTestOnly()
    newKeyAllowedMap.clear()
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. Users can generate new keys
   * with this manager using the {@link Registry# newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or the existing key manager could not create
   * new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *                                  class of {@code manager}, or the registration tries to re-enable the generation of new
   *                                  keys.
   */
  @throws[GeneralSecurityException]
  def registerKeyManager[P](manager: KeyManager[P]): Unit = {
    registerKeyManager(manager, /* newKeyAllowed= */ true)
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry# newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *                                  class of {@code manager}, or the registration tries to re-enable the generation of new
   *                                  keys.
   */
  @throws[GeneralSecurityException]
  def registerKeyManager[P](manager: KeyManager[P], newKeyAllowed: Boolean): Unit = {
    if (manager == null) throw new IllegalArgumentException("key manager must be non-null.")
    val newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get)
    newKeyManagerRegistry.registerKeyManager(manager)
    val typeUrl = manager.getKeyType
    ensureKeyManagerInsertable(typeUrl, newKeyAllowed)
    newKeyAllowedMap.put(typeUrl, newKeyAllowed)
    keyManagerRegistry.set(newKeyManagerRegistry)
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry# newKey} methods.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * <p>If {@code newKeyAllowed} is true, also tries to register the key templates supported by
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *                                  class of {@code manager}, or the registration tries to re-enable the generation of new
   *                                  keys.
   * @throws GeneralSecurityException if there's an existing key template.
   * @throws GeneralSecurityException if the key manager is not compatible with the restrictions in
   *                                  FIPS-mode.
   */
  @throws[GeneralSecurityException]
  def registerKeyManager[KeyProtoT <: KeyProto](manager: KeyTypeManager[KeyProtoT], newKeyAllowed: Boolean): Unit = {
    if (manager == null) throw new IllegalArgumentException("key manager must be non-null.")
    val newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get)
    newKeyManagerRegistry.registerKeyManager(manager)
    val typeUrl = manager.getKeyType
    ensureKeyManagerInsertable(typeUrl, //newKeyAllowed ? manager.keyFactory().keyFormats() : Collections.emptyMap(),
      newKeyAllowed)
    newKeyAllowedMap.put(typeUrl, newKeyAllowed)
    keyManagerRegistry.set(newKeyManagerRegistry)
  }

  /**
   * Tries to register {@code manager} for the given {@code typeUrl}. Users can generate new keys
   * with this manager using the {@link Registry# newKey} methods.
   *
   * <p>Does nothing if there's an existing key manager and it's an instance of the same class as
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   *                                  of the same class as {@code manager}
   * @deprecated use {@link # registerKeyManager ( KeyManager ) registerKeyManager(KeyManager&lt;P&gt;)}
   */
  @deprecated
  @throws[GeneralSecurityException]
  def registerKeyManager[P](typeUrl: String, manager: KeyManager[P]): Unit = {
    registerKeyManager(typeUrl, manager, /* newKeyAllowed= */ true)
  }

  /**
   * Tries to register {@code manager} for the given {@code typeUrl}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry# newKey} methods.
   *
   * <p>Does nothing if there's an existing key manager and it's an instance of the same class as
   * {@code manager}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   *                                  of the same class as {@code manager}
   * @deprecated use {@link # registerKeyManager ( KeyManager, boolean)
   *     registerKeyManager(KeyManager&lt;P&gt;, boolean)}
   */
  @deprecated
  @throws[GeneralSecurityException]
  def registerKeyManager[P](typeUrl: String, manager: KeyManager[P], newKeyAllowed: Boolean): Unit = {
    if (manager == null) throw new IllegalArgumentException("key manager must be non-null.")
    if (!(typeUrl == manager.getKeyType)) throw new GeneralSecurityException("Manager does not support key type " + typeUrl + ".")
    registerKeyManager(manager, newKeyAllowed)
  }

  /**
   * Throws a general security exception if one of these conditions holds:
   *
   * <ul>
   * <li>There is already a key manager registered for {@code typeURL}, and at least one of the
   * following is true:
   * <ul>
   * <li>The class implementing the existing key manager differs from the given one.
   * <li>The value of {@code newKeyAllowed} currently registered is false, but the input
   * parameter is true.
   * </ul>
   * <li>The {@code newKeyAllowed} flag is true, and at least one of the following is true:
   * <ul>
   * <li>The key manager was already registered, but it contains new key templates.
   * <li>The key manager is new, but it contains existing key templates.
   */
  @throws[GeneralSecurityException]
  private def ensureKeyManagerInsertable[KeyProtoT <: KeyProto](typeUrl: String, newKeyAllowed: Boolean): Unit = {
    if (newKeyAllowed && newKeyAllowedMap.contains(typeUrl) && !newKeyAllowedMap(typeUrl)) {
      throw new GeneralSecurityException("New keys are already disallowed for key type " + typeUrl)
    }
  }

  /**
   * Tries to register {@code manager} for {@code manager.getKeyType()}. If {@code newKeyAllowed} is
   * true, users can generate new keys with this manager using the {@link Registry# newKey} methods.
   *
   * <p>If {@code newKeyAllowed} is true, also tries to register the key templates supported by
   * {@code manager}.
   *
   * <p>If there is an existing key manager, throws an exception if {@code manager} and the existing
   * key manager aren't instances of the same class, or if {@code newKeyAllowed} is true while the
   * existing key manager could not create new keys. Otherwise registration succeeds.
   *
   * @throws GeneralSecurityException if there's an existing key manager is not an instance of the
   *                                  class of {@code manager}, or the registration tries to re-enable the generation of new
   *                                  keys.
   * @throws GeneralSecurityException if there's an existing key template.
   */
  @throws[GeneralSecurityException]
  def registerAsymmetricKeyManagers[KeyProtoT <: KeyProto, PublicKeyProtoT <: PublicKeyProto](privateKeyTypeManager: PrivateKeyTypeManager[KeyProtoT, PublicKeyProtoT], publicKeyTypeManager: KeyTypeManager[PublicKeyProtoT], newKeyAllowed: Boolean): Unit = {
    if (privateKeyTypeManager == null || publicKeyTypeManager == null) throw new IllegalArgumentException("given key managers must be non-null.")
    val newKeyManagerRegistry = new KeyManagerRegistry(keyManagerRegistry.get)
    newKeyManagerRegistry.registerAsymmetricKeyManagers(privateKeyTypeManager, publicKeyTypeManager)
    val privateTypeUrl = privateKeyTypeManager.getKeyType
    val publicTypeUrl = publicKeyTypeManager.getKeyType
    ensureKeyManagerInsertable(privateTypeUrl, newKeyAllowed)
    // No key format because a public key manager cannot create new keys
    ensureKeyManagerInsertable(publicTypeUrl, false)
    newKeyAllowedMap.put(privateTypeUrl, newKeyAllowed)
    newKeyAllowedMap.put(publicTypeUrl, false)
    keyManagerRegistry.set(newKeyManagerRegistry)
  }

  /**
   * Tries to register {@code wrapper} as a new SetWrapper for primitive {@code P}.
   *
   * <p>If no SetWrapper is registered for {@code P}, registers the given one. If there already is a
   * SetWrapper registered which is of the same class ass the passed in set wrapper, the call is
   * silently ignored. If the new set wrapper is of a different type, the call fails with a {@code
   * GeneralSecurityException}.
   *
   * @throws GeneralSecurityException if there's an existing key manager and it is not an instance
   * of the class of {@code manager}, or the registration tries to re-enable the generation of
   * new keys.
   */
  @throws[GeneralSecurityException]
  def registerPrimitiveWrapper[B, P](wrapper: PrimitiveWrapper[B, P]): Unit = {
    MutablePrimitiveRegistry.globalInstance.registerPrimitiveWrapper(wrapper)
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} (if found).
   * @deprecated Use {@code getKeyManager(typeUrl, Primitive.class)} or {@code getUntypedKeyManager
   *     typeUrl} instead.
   */
  @deprecated
  @throws[GeneralSecurityException]
  def getKeyManager[P](typeUrl: String): KeyManager[P] = keyManagerRegistry.get.getKeyManager(typeUrl)

  /** @return a {@link KeyManager} for the given {@code typeUrl} (if found). */
  @throws[GeneralSecurityException]
  def getKeyManager[P](typeUrl: String, primitiveClass: Class[P]): KeyManager[P] = keyManagerRegistry.get.getKeyManager(typeUrl, primitiveClass)

  /** @return a {@link KeyManager} for the given {@code typeUrl} (if found). */
  @throws[GeneralSecurityException]
  def getUntypedKeyManager(typeUrl: String): KeyManager[_] = keyManagerRegistry.get.getUntypedKeyManager(typeUrl)

  /**
   * Convenience method for generating a new {@link KeyData} for the specified {@code template}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager# newKeyData}.
   *
   * <p>This method should be used solely for key management.
   *
   * @return a new {@link KeyData}
   */
  @throws[GeneralSecurityException]
  def newKeyData(keyTemplate: com.google.crypto.tink.proto.KeyTemplate): KeyData = {
    val manager = getUntypedKeyManager(keyTemplate.getTypeUrl)
    if (newKeyAllowedMap(keyTemplate.getTypeUrl)) manager.newKeyData
    else throw new GeneralSecurityException("newKey-operation not permitted for key type " + keyTemplate.getTypeUrl)
  }

  /**
   * Convenience method for generating a new {@link KeyData} for the specified {@code template}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyTemplate.type_url}, and calls
   * {@link KeyManager# newKeyData}.
   *
   * <p>This method should be used solely for key management.
   *
   * @return a new {@link KeyData}
   */
  @throws[GeneralSecurityException]
  def newKeyData(keyTemplate: com.google.crypto.tink.KeyTemplate): KeyData = {
    newKeyData(keyTemplate.getProto)
  }

  /**
   * Convenience method for extracting the public key data from the private key given in {@code
   * serializedPrivateKey}.
   *
   * <p>It looks up a {@link PrivateKeyManager} identified by {@code typeUrl}, and calls {@link
 * PrivateKeyManager#getPublicKeyData} with {@code serializedPrivateKey} as the parameter.
   *
   * @return a new key
   */
  @throws[GeneralSecurityException]
  def getPublicKeyData(typeUrl: String, privateKeyProto: KeyProto): KeyData = {
    val manager = getKeyManager(typeUrl)
    if (!manager.isInstanceOf[PrivateKeyManager[_]]) throw new GeneralSecurityException("manager for key type " + typeUrl + " is not a PrivateKeyManager")
    manager.asInstanceOf[PrivateKeyManager[_]].getPublicKeyData(privateKeyProto)
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code proto}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
 * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(typeUrl, key, P.class)} instead.
   */
  @SuppressWarnings(Array("TypeParameterUnusedInFormals"))
  @deprecated
  @throws[GeneralSecurityException]
  def getPrimitive[P](typeUrl: String, key: KeyProto): P = {
    val manager = keyManagerRegistry.get.getKeyManager(typeUrl)
    manager.getPrimitive(key)
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code key}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code type_url}, and calls {@link
 * KeyManager#getPrimitive} with {@code key} as the parameter.
   *
   * @return a new primitive
   */
  @throws[GeneralSecurityException]
  def getPrimitive[P](typeUrl: String, key: KeyProto, primitiveClass: Class[P]): P = {
    val manager = keyManagerRegistry.get.getKeyManager(typeUrl, primitiveClass)
    manager.getPrimitive(key)
  }

  /**
   * Convenience method for creating a new primitive for the key given in {@code keyData}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyData.type_url}, and calls {@link
 * KeyManager#getPrimitive} with {@code keyData.value} as the parameter.
   *
   * @return a new primitive
   * @deprecated Use {@code getPrimitive(keyData, Primitive.class)} instead.
   */
  @deprecated /* Deprecation under consideration */
  @SuppressWarnings(Array("TypeParameterUnusedInFormals"))
  @throws[GeneralSecurityException]
  def getPrimitive[P](keyData: KeyData): P = getPrimitive(keyData.getTypeUrl, keyData.getValue)

  /**
   * Convenience method for creating a new primitive for the key given in {@code keyData}.
   *
   * <p>It looks up a {@link KeyManager} identified by {@code keyData.type_url}, and calls {@link
 * KeyManager#getPrimitive} with {@code keyData.value} as the parameter.
   *
   * @return a new primitive
   */
  @throws[GeneralSecurityException]
  def getPrimitive[P](keyData: KeyData, primitiveClass: Class[P]): P = getPrimitive(keyData.getTypeUrl, keyData.getValue, primitiveClass)

  @throws[GeneralSecurityException]
  private[tink] def getFullPrimitive[KeyT <: Key, P](key: KeyT, primitiveClass: Class[P]) = MutablePrimitiveRegistry.globalInstance.getPrimitive(key, primitiveClass)

  /**
   * Looks up the globally registered PrimitiveWrapper for this primitive and wraps the given
   * PrimitiveSet with it.
   */
  @throws[GeneralSecurityException]
  def wrap[B, P](primitiveSet: PrimitiveSet[B], clazz: Class[P]): P = MutablePrimitiveRegistry.globalInstance.wrap(primitiveSet, clazz)

  @throws[GeneralSecurityException]
  def wrap[P](primitiveSet: PrimitiveSet[P]): P = wrap(primitiveSet, primitiveSet.getPrimitiveClass)

  /**
   * Returns the input primitive required when creating a {@code wrappedPrimitive}.
   *
   * <p>This returns the primitive class of the objects required when we want to create a wrapped
   * primitive of type {@code wrappedPrimitive}. Returns {@code null} if no wrapper for this
   * primitive has been registered.
   */
  def getInputPrimitive(wrappedPrimitive: Class[_]): Class[_] = try MutablePrimitiveRegistry.globalInstance.getInputPrimitiveClass(wrappedPrimitive)
  catch {
    case e: GeneralSecurityException =>
      null
  }
}