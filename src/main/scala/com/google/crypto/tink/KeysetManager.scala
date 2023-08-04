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

import com.google.crypto.tink.internal.KeyStatusTypeProtoConverter
import com.google.crypto.tink.internal.Util
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.tinkkey.KeyAccess
import com.google.crypto.tink.tinkkey.KeyHandle
import com.google.crypto.tink.tinkkey.SecretKeyAccess
import com.google.crypto.tink.tinkkey.internal.ProtoKey
import java.security.GeneralSecurityException

/**
 * Manages a {@link Keyset} proto, with convenience methods that rotate, disable, enable or destroy
 * keys.
 *
 * @since 1.0.0
 */
object KeysetManager {
  /** @return a {@link KeysetManager} for the keyset manged by {@code val} */
  def withKeysetHandle(`val`: KeysetHandle) = new KeysetManager(`val`.getKeyset.toBuilder)

  /** @return a {@link KeysetManager} for an empty keyset. */
  def withEmptyKeyset = new KeysetManager(Keyset.newBuilder)
}

final class KeysetManager private(private val keysetBuilder: Keyset.Builder) {
  /** @return a {@link KeysetHandle} of the managed keyset */
  @throws[GeneralSecurityException]
  def getKeysetHandle: KeysetHandle = KeysetHandle.fromKeyset(keysetBuilder.build)

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}, and sets the new key as the
   * primary key.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *                                  keyTemplate}
   * @deprecated                      Please use {@link # add}. This method adds a new key and immediately promotes it to
   *                                  primary. However, when you do keyset rotation, you almost never want to make the new key
   *                                  primary, because old binaries don't know the new key yet.
   */
  //@CanIgnoreReturnValue
  @deprecated /* Deprecation under consideration */
  @throws[GeneralSecurityException]
  def rotate(keyTemplate: com.google.crypto.tink.proto.KeyTemplate): KeysetManager = {
    addNewKey(keyTemplate, true)
    this
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *                                  keyTemplate}
   * @deprecated                      This method takes a KeyTemplate proto, which is an internal implementation detail.
   *                                  Please use the add method that takes a {@link KeyTemplate} POJO.
   */
  //@CanIgnoreReturnValue
  @deprecated /* Deprecation under consideration */
  @throws[GeneralSecurityException]
  def add(keyTemplate: com.google.crypto.tink.proto.KeyTemplate): KeysetManager = {
    addNewKey(keyTemplate, false)
    this
  }

  /**
   * Generates and adds a fresh key generated using {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if cannot find any {@link KeyManager} that can handle {@code
   *                                  keyTemplate}
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def add(keyTemplate: KeyTemplate): KeysetManager = {
    addNewKey(keyTemplate.getProto, false)
    this
  }

  /**
   * Adds the input {@link KeyHandle} to the existing keyset. The KeyStatusType and key ID of the
   * {@link KeyHandle} are used as-is in the keyset.
   *
   * @throws UnsupportedOperationException if the {@link KeyHandle} contains a {@link TinkKey} which
   *                                       is not a {@link ProtoKey}.
   * @throws GeneralSecurityException      if the {@link KeyHandle}'s key ID collides with another key ID
   *                                       in the keyset.
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def add(keyHandle: KeyHandle): KeysetManager = {
    var pkey: ProtoKey = null
    try pkey = keyHandle.getKey(SecretKeyAccess.insecureSecretAccess).asInstanceOf[ProtoKey]
    catch {
      case e: ClassCastException =>
        throw new UnsupportedOperationException("KeyHandles which contain TinkKeys that are not ProtoKeys are not yet supported.", e)
    }
    if (keyIdExists(keyHandle.getId)) throw new GeneralSecurityException("Trying to add a key with an ID already contained in the keyset.")
    keysetBuilder.addKey(
      Keyset.Key.newBuilder
        .setKeyData(pkey.getProtoKey)
        .setKeyId(keyHandle.getId)
        .setStatus(KeyStatusTypeProtoConverter.toProto(keyHandle.getStatus))
        .setOutputPrefixType(KeyTemplate.toProto(pkey.getOutputPrefixType))
        .build
    )
    this
  }

  /**
   * Adds the input {@code KeyHandle} to the existing keyset with {@code OutputPrefixType.TINK}.
   *
   * @throws GeneralSecurityException      if the given {@code KeyAccess} does not grant access to the
   *                                       key contained in the {@code KeyHandle}.
   * @throws UnsupportedOperationException if the {@code KeyHandle} contains a {@code TinkKey} which
   *                                       is not a {@code ProtoKey}.
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def add(keyHandle: KeyHandle, access: KeyAccess): KeysetManager = add(keyHandle)

  /**
   * Generates a fresh key using {@code keyTemplate} and returns the {@code keyId} of it. In case
   * {@code asPrimary} is true the generated key will be the new primary.
   *
   * @deprecated Please use {@link # add}. This method adds a new key and when {@code asPrimary} is
   *             true immediately promotes it to primary. However, when you do keyset rotation, you almost
   *             never want to make the new key primary, because old binaries don't know the new key yet.
   */
  //@CanIgnoreReturnValue
  @deprecated /* Deprecation under consideration */
  @throws[GeneralSecurityException]
  def addNewKey(keyTemplate: com.google.crypto.tink.proto.KeyTemplate, asPrimary: Boolean): Int = {
    val key = newKey(keyTemplate)
    keysetBuilder.addKey(key)
    if (asPrimary) keysetBuilder.setPrimaryKeyId(key.getKeyId)
    key.getKeyId
  }

  /**
   * Sets the key with {@code keyId} as primary.
   *
   * @throws GeneralSecurityException if the key is not found or not enabled
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def setPrimary(keyId: Int): KeysetManager = {

    keysetBuilder.getKeyList.find(_.getKeyId == keyId) match
      case Some(key) =>
        if (!(key.getStatus == KeyStatusType.ENABLED)) throw new GeneralSecurityException("cannot set key as primary because it's not enabled: " + keyId)
        keysetBuilder.setPrimaryKeyId(keyId)
        this
      case None =>
          throw new GeneralSecurityException("key not found: " + keyId)
  }

  /**
   * Enables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found
   */
  @throws[GeneralSecurityException]
  def enable(keyId: Int): KeysetManager = {
    keysetBuilder.getKeyList.zipWithIndex.find((key, i) => key.keyId == keyId) match
      case Some((key, i)) =>
        if ((key.getStatus ne KeyStatusType.ENABLED) && (key.getStatus ne KeyStatusType.DISABLED)) throw new GeneralSecurityException("cannot enable key with id " + keyId)
        keysetBuilder.setKey(i, key.toBuilder.setStatus(KeyStatusType.ENABLED).build)
        this
      case None =>
          throw new GeneralSecurityException("key not found: " + keyId)
  }

  /**
   * Disables the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def disable(keyId: Int): KeysetManager = {
    if (keyId == keysetBuilder.getPrimaryKeyId) throw new GeneralSecurityException("cannot disable the primary key")

    keysetBuilder.getKeyList.zipWithIndex.find((key, i) => key.keyId == keyId) match
      case Some((key, i)) =>
        if ((key.getStatus ne KeyStatusType.ENABLED) && (key.getStatus ne KeyStatusType.DISABLED)) throw new GeneralSecurityException("cannot disable key with id " + keyId)
        keysetBuilder.setKey(i, key.toBuilder.setStatus(KeyStatusType.DISABLED).build)
        this
      case None =>
          throw new GeneralSecurityException("key not found: " + keyId)
  }

  /**
   * Deletes the key with {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def delete(keyId: Int): KeysetManager = {
    if (keyId == keysetBuilder.getPrimaryKeyId) throw new GeneralSecurityException("cannot delete the primary key")

    val i = keysetBuilder.getKeyList.indexWhere(_.getKeyId == keyId)
    if (i < 0) throw new GeneralSecurityException("key not found: " + keyId)

    keysetBuilder.removeKey(i)
    this
  }

  /**
   * Destroys the key material associated with the {@code keyId}.
   *
   * @throws GeneralSecurityException if the key is not found or it is the primary key
   */
  //@CanIgnoreReturnValue
  @throws[GeneralSecurityException]
  def destroy(keyId: Int): KeysetManager = {
    if (keyId == keysetBuilder.getPrimaryKeyId) throw new GeneralSecurityException("cannot destroy the primary key")
    keysetBuilder.getKeyList.zipWithIndex.find((key, i) => key.keyId == keyId) match
      case Some((key, i)) =>
        if ((key.getStatus ne KeyStatusType.ENABLED) && (key.getStatus ne KeyStatusType.DISABLED) && (key.getStatus ne KeyStatusType.DESTROYED)) throw new GeneralSecurityException("cannot destroy key with id " + keyId)
        keysetBuilder.setKey(i, key.toBuilder.setStatus(KeyStatusType.DESTROYED).clearKeyData().build)
        return this
      case None =>
          throw new GeneralSecurityException("key not found: " + keyId)
  }

  @throws[GeneralSecurityException]
  private def newKey(keyTemplate: com.google.crypto.tink.proto.KeyTemplate) = createKeysetKey(Registry.newKeyData(keyTemplate), keyTemplate.getOutputPrefixType)

  @throws[GeneralSecurityException]
  private def createKeysetKey(keyData: KeyData, outputPrefixType: OutputPrefixType) = {
    val keyId = newKeyId
    if (outputPrefixType eq OutputPrefixType.UNKNOWN_PREFIX) throw new GeneralSecurityException("unknown output prefix type")
    Keyset.Key.newBuilder.setKeyData(keyData).setKeyId(keyId).setStatus(KeyStatusType.ENABLED).setOutputPrefixType(outputPrefixType).build
  }

  private def keyIdExists(keyId: Int): Boolean = {
    keysetBuilder.getKeyList.exists(_.keyId == keyId)
  }

  private def newKeyId = {
    var keyId = Util.randKeyId
    while (keyIdExists(keyId)) keyId = Util.randKeyId
    keyId
  }
}