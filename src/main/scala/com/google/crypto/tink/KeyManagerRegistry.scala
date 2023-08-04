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

import com.google.crypto.tink.internal.KeyTypeManager
import com.google.crypto.tink.internal.PrivateKeyTypeManager
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.proto.KeyProto
import com.google.crypto.tink.proto.PublicKeyProto
import java.security.GeneralSecurityException
import java.util.Collections
import java.util
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import java.util.logging.Logger

/**
 * An internal API to register KeyManagers and KeyTypeManagers.
 *
 * <p>The KeyManagerRegistry provides an API to register Key(Type)Managers, ensuring FIPS
 * compatibility. For registered managers, it gives access to the following operations:
 *
 * <ul>
 * <li>Retrive KeyManagers (but not KeyTypeManagers)
 * <li>Parsing keys (only if KeyTypeManagers have been registered)
 * </ul>
 */
object KeyManagerRegistry {
  private val logger = Logger.getLogger(classOf[KeyManagerRegistry].getName)

  /**
   * A container which either is constructed from a {@link KeyTypeManager} or from a {@link
 * KeyManager}.
   */
  private trait KeyManagerContainer {
    /**
     * Returns the KeyManager for the given primitive or throws if the given primitive is not in
     * supportedPrimitives.
     */
    @throws[GeneralSecurityException]
    def getKeyManager[P](primitiveClass: Class[P]): KeyManager[P]

    /**
     * Returns a KeyManager from the given container. If a KeyTypeManager has been provided, creates
     * a KeyManager for some primitive.
     */
    def getUntypedKeyManager: KeyManager[?]

    /**
     * The Class object corresponding to the actual KeyTypeManager/KeyManager used to build this
     * object.
     */
    def getImplementingClass: Class[?]

    /**
     * The primitives supported by the underlying {@link KeyTypeManager} resp. {@link KeyManager}.
     */
    def supportedPrimitives: Set[Class[?]]

    /**
     * The Class object corresponding to the public key manager when this key manager was registered
     * as first argument with "registerAsymmetricKeyManagers". Null otherwise.
     */
    def publicKeyManagerClassOrNull: Class[?]

    /**
     * Validates the key. Only works if the key type has been
     * registered with a KeyTypeManager, returns null otherwise.
     *
     * <p>Can throw exceptions if validation fails or if parsing fails.
     */
    @throws[GeneralSecurityException]
    def validateKey(keyProto: KeyProto): Unit
  }

  private def createContainerFor[P](keyManager: KeyManager[P]) = {
    val localKeyManager = keyManager
    new KeyManagerRegistry.KeyManagerContainer() {
      @throws[GeneralSecurityException]
      override def getKeyManager[Q](primitiveClass: Class[Q]): KeyManager[Q] = {
        if (!(localKeyManager.getPrimitiveClass == primitiveClass)) throw new InternalError("This should never be called, as we always first check supportedPrimitives.")
        @SuppressWarnings(Array("unchecked")) // We checked equality of the primitiveClass objects.
        val result: KeyManager[Q] = localKeyManager.asInstanceOf[KeyManager[Q]]
        result
      }

      override def getUntypedKeyManager: KeyManager[?] = return localKeyManager

      override def getImplementingClass: Class[?] = return localKeyManager.getClass

      override def supportedPrimitives: Set[Class[?]] = Set(localKeyManager.getPrimitiveClass)

      override def publicKeyManagerClassOrNull: Class[?] = return null

      @throws[GeneralSecurityException]
      override def validateKey(serializedKey: KeyProto): Unit = {
      }
    }
  }

  private def createContainerFor[KeyProtoT <: KeyProto](keyManager: KeyTypeManager[KeyProtoT]) = {
    val localKeyManager = keyManager
    new KeyManagerRegistry.KeyManagerContainer() {
      @throws[GeneralSecurityException]
      override def getKeyManager[Q](primitiveClass: Class[Q]): KeyManager[Q] = try return new KeyManagerImpl[Q, KeyProtoT](localKeyManager, primitiveClass)
      catch {
        case e: IllegalArgumentException =>
          throw new GeneralSecurityException("Primitive type not supported", e)
      }

      override def getUntypedKeyManager: KeyManager[?] = {
        val primitiveClass = localKeyManager.firstSupportedPrimitiveClass
        new KeyManagerImpl(localKeyManager, primitiveClass)
      }

      override def getImplementingClass: Class[?] = return localKeyManager.getClass

      override def supportedPrimitives: Set[Class[?]] = localKeyManager.supportedPrimitives

      override def publicKeyManagerClassOrNull: Class[?] = return null

      @throws[GeneralSecurityException]
      override def validateKey(keyProto: KeyProto): Unit = {
        val key: KeyProtoT = try keyProto.asInstanceOf[KeyProtoT]
        catch {
          case e: ClassCastException =>
            throw new GeneralSecurityException(e)
        }
        localKeyManager.validateKey(key)
      }
    }
  }

  private def createPrivateKeyContainerFor[KeyProtoT <: KeyProto, PublicKeyProtoT <: PublicKeyProto](privateKeyTypeManager: PrivateKeyTypeManager[KeyProtoT, PublicKeyProtoT], publicKeyTypeManager: KeyTypeManager[PublicKeyProtoT]) = {
    val localPrivateKeyManager = privateKeyTypeManager
    val localPublicKeyManager = publicKeyTypeManager
    new KeyManagerRegistry.KeyManagerContainer() {
      @throws[GeneralSecurityException]
      override def getKeyManager[Q](primitiveClass: Class[Q]): KeyManager[Q] = try return new PrivateKeyManagerImpl[Q, KeyProtoT, PublicKeyProtoT](localPrivateKeyManager, localPublicKeyManager, primitiveClass)
      catch {
        case e: IllegalArgumentException =>
          throw new GeneralSecurityException("Primitive type not supported", e)
      }

      override def getUntypedKeyManager: KeyManager[?] = return new PrivateKeyManagerImpl(localPrivateKeyManager, localPublicKeyManager, localPrivateKeyManager.firstSupportedPrimitiveClass)

      override def getImplementingClass: Class[?] = return localPrivateKeyManager.getClass

      override def supportedPrimitives: Set[Class[?]] = return localPrivateKeyManager.supportedPrimitives

      override def publicKeyManagerClassOrNull: Class[?] = return localPublicKeyManager.getClass

      @throws[GeneralSecurityException]
      override def validateKey(keyProto: KeyProto): Unit = {
        val key: KeyProtoT = try keyProto.asInstanceOf[KeyProtoT]
        catch {
          case e: ClassCastException =>
            throw new GeneralSecurityException(e)
        }
        localPrivateKeyManager.validateKey(key)
      }
    }
  }

  /** Helper method to check if an instance is not null; taken from guava's Precondition.java */
  private def checkNotNull[T](reference: T) = {
    if (reference == null) throw new NullPointerException
    reference
  }

  private def toCommaSeparatedString(setOfClasses: Set[Class[?]]) = {
    val b = new StringBuilder()
    var first = true
    for (clazz <- setOfClasses) {
      if (!first) b.append(", ")
      b.append(clazz.getCanonicalName)
      first = false
    }
    b.toString
  }
}

final class KeyManagerRegistry private[tink] {
  // A map from the TypeUrl to the KeyManagerContainer.
  private var keyManagerMap: ConcurrentMap[String, KeyManagerRegistry.KeyManagerContainer] = new ConcurrentHashMap[String, KeyManagerRegistry.KeyManagerContainer]

  def this(original: KeyManagerRegistry) = {
    this()
    keyManagerMap = new ConcurrentHashMap[String, KeyManagerRegistry.KeyManagerContainer](original.keyManagerMap)
  }

  @throws[GeneralSecurityException]
  private def getKeyManagerContainerOrThrow(typeUrl: String) = {
    if (!keyManagerMap.containsKey(typeUrl)) throw new GeneralSecurityException("No key manager found for key type " + typeUrl)
    keyManagerMap.get(typeUrl)
  }

  @throws[GeneralSecurityException]
  private def registerKeyManagerContainer[P](containerToInsert: KeyManagerRegistry.KeyManagerContainer, forceOverwrite: Boolean): Unit = {
    val typeUrl = containerToInsert.getUntypedKeyManager.getKeyType
    val container = keyManagerMap.get(typeUrl)
    if (container != null && !(container.getImplementingClass == containerToInsert.getImplementingClass)) {
      KeyManagerRegistry.logger.warning("Attempted overwrite of a registered key manager for key type " + typeUrl)
      throw new GeneralSecurityException(String.format("typeUrl (%s) is already registered with %s, cannot be re-registered with %s", typeUrl, container.getImplementingClass.getName, containerToInsert.getImplementingClass.getName))
    }
    if (!forceOverwrite) keyManagerMap.putIfAbsent(typeUrl, containerToInsert)
    else keyManagerMap.put(typeUrl, containerToInsert)
  }

  /**
   * Attempts to insert the given KeyManager into the object.
   *
   * <p>If this fails, the KeyManagerRegistry is in an unspecified state and should be discarded.
   */
  @throws[GeneralSecurityException]
  private[tink] def registerKeyManager[P](manager: KeyManager[P]): Unit = {
    registerKeyManagerContainer(KeyManagerRegistry.createContainerFor(manager), /* forceOverwrite= */ false)
  }

  @throws[GeneralSecurityException]
  private[tink] def registerKeyManager[KeyProtoT <: KeyProto](manager: KeyTypeManager[KeyProtoT]): Unit = {
    registerKeyManagerContainer(KeyManagerRegistry.createContainerFor(manager), /* forceOverwrite= */ false)
  }

  /**
   * Registers a private KeyTypeManager and a corresponding public KeyTypeManager.
   *
   * <p>On the generated Private KeyManager, when we create the public key from a private key, we
   * also call "Validate" on the provided public KeyTypeManager.
   *
   * <p>A call to registerAsymmetricKeyManager takes precedence over other calls (i.e., if the above
   * association is established once, it will stay established).
   */
  @throws[GeneralSecurityException]
  private[tink] def registerAsymmetricKeyManagers[KeyProtoT <: KeyProto, PublicKeyProtoT <: PublicKeyProto](privateKeyTypeManager: PrivateKeyTypeManager[KeyProtoT, PublicKeyProtoT], publicKeyTypeManager: KeyTypeManager[PublicKeyProtoT]): Unit = {
    val privateTypeUrl = privateKeyTypeManager.getKeyType
    val publicTypeUrl = publicKeyTypeManager.getKeyType
    if (keyManagerMap.containsKey(privateTypeUrl) && keyManagerMap.get(privateTypeUrl).publicKeyManagerClassOrNull != null) {
      val existingPublicKeyManagerClass = keyManagerMap.get(privateTypeUrl).publicKeyManagerClassOrNull
      if (existingPublicKeyManagerClass != null) if (!(existingPublicKeyManagerClass.getName == publicKeyTypeManager.getClass.getName)) {
        KeyManagerRegistry.logger.warning("Attempted overwrite of a registered key manager for key type " + privateTypeUrl + " with inconsistent public key type " + publicTypeUrl)
        throw new GeneralSecurityException(String.format("public key manager corresponding to %s is already registered with %s, cannot" + " be re-registered with %s", privateKeyTypeManager.getClass.getName, existingPublicKeyManagerClass.getName, publicKeyTypeManager.getClass.getName))
      }
    }
    // We overwrite such that if we once register asymmetrically and once symmetrically, the
    // asymmetric one takes precedence.
    registerKeyManagerContainer(KeyManagerRegistry.createPrivateKeyContainerFor(privateKeyTypeManager, publicKeyTypeManager), /* forceOverwrite= */ true)
    registerKeyManagerContainer(KeyManagerRegistry.createContainerFor(publicKeyTypeManager), /* forceOverwrite= */ false)
  }

  private[tink] def typeUrlExists(typeUrl: String) = keyManagerMap.containsKey(typeUrl)

  /**
   * Should not be used since the API is a misuse of Java generics.
   *
   * @deprecated
   */
  @deprecated
  @throws[GeneralSecurityException]
  private[tink] /* Deprecation under consideration */ def getKeyManager[P](typeUrl: String) = getKeyManagerInternal[P](typeUrl, null)

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} and {@code primitiveClass}(if found
   *         and this key type supports this primitive).
   */
  @throws[GeneralSecurityException]
  private[tink] def getKeyManager[P](typeUrl: String, primitiveClass: Class[P]) = getKeyManagerInternal(typeUrl, KeyManagerRegistry.checkNotNull(primitiveClass))

  @throws[GeneralSecurityException]
  private def getKeyManagerInternal[P](typeUrl: String, primitiveClass: Class[P]): KeyManager[P] = {
    val container = getKeyManagerContainerOrThrow(typeUrl)
    if (primitiveClass == null) {
      @SuppressWarnings(Array("unchecked")) // Only called from deprecated functions; unavoidable there.
      val result: KeyManager[P] = container.getUntypedKeyManager.asInstanceOf[KeyManager[P]]
      return result
    }
    if (container.supportedPrimitives.contains(primitiveClass)) return container.getKeyManager(primitiveClass)
    throw new GeneralSecurityException("Primitive type " + primitiveClass.getName + " not supported by key manager of type " + container.getImplementingClass + ", supported primitives: " + KeyManagerRegistry.toCommaSeparatedString(container.supportedPrimitives))
  }

  /**
   * @return a {@link KeyManager} for the given {@code typeUrl} (if found).
   */
  @throws[GeneralSecurityException]
  private[tink] def getUntypedKeyManager(typeUrl: String) = {
    val container = getKeyManagerContainerOrThrow(typeUrl)
    container.getUntypedKeyManager
  }

  private[tink] def isEmpty = keyManagerMap.isEmpty
}