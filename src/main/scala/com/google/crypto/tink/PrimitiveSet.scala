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

import com.google.crypto.tink.internal.{ProtoKeySerialization, SerializationRegistry}
import com.google.crypto.tink.proto.{KeyStatusType, Keyset, OutputPrefixType}
import com.google.crypto.tink.subtle.Hex

import java.security.GeneralSecurityException
import scala.collection.mutable

/**
 * A container class for a set of primitives -- implementations of cryptographic primitives offered
 * by Tink.
 *
 * <p>It provides also additional properties for the primitives it holds. In particular, one of the
 * primitives in the set can be distinguished as "the primary" one.
 *
 * <p>PrimitiveSet is an auxiliary class used for supporting key rotation: primitives in a set
 * correspond to keys in a keyset. Users will usually work with primitive instances, which
 * essentially wrap primitive sets. For example an instance of an Aead-primitive for a given keyset
 * holds a set of Aead-primitives corresponding to the keys in the keyset, and uses the set members
 * to do the actual crypto operations: to encrypt data the primary Aead-primitive from the set is
 * used, and upon decryption the ciphertext's prefix determines the id of the primitive from the
 * set.
 *
 * <p>PrimitiveSet is a public class to allow its use in implementations of custom primitives.
 *
 * @since 1.0.0
 */
object PrimitiveSet {
  /**
   * A single entry in the set. In addition to the actual primitive it holds also some extra
   * information about the primitive.
   */
  final class Entry[P] private[tink]( // If set, this is a primitive of a key.
                                      private val fullPrimitive: Option[P],
                                      private val primitive: Option[P],
                                      _identifier: Array[Byte], // The status of the key represented by the primitive.
                                      private val status: KeyStatusType, // The output prefix type of the key represented by the primitive.
                                      private val outputPrefixType: OutputPrefixType, // The id of the key.
                                      private val keyId: Int,
                                      private val keyType: String,
                                      private val key: Key) {

    // Identifies the primitive within the set.
    final private val identifier: Array[Byte] = Array.copyOf(_identifier, _identifier.length) // It is the ciphertext prefix of the corresponding key.


    /**
     * Returns the full primitive for this entry.
     *
     * <p>This is used in cases when the new Tink Key interface is used and the primitive is
     * self-sufficient by itself, meaning that all the necessary information to process the
     * primitive is contained in the primitive (most likely through the new Key interface), as
     * opposed to the {@code primitive} field (see {@link # getPrimitive} for details).
     */
    def getFullPrimitive: P = this.fullPrimitive.get

    /**
     * Returns the primitive for this entry.
     *
     * <p>For primitives of type {@code Mac}, {@code Aead}, {@code PublicKeySign}, {@code
     * PublicKeyVerify}, {@code DeterministicAead}, {@code HybridEncrypt}, and {@code HybridDecrypt}
     * this is a primitive which <b>ignores</b> the output prefix and assumes "RAW".
     */
    def getPrimitive: P = this.primitive.get

    def getStatus: KeyStatusType = status

    def getOutputPrefixType: OutputPrefixType = outputPrefixType

    final def getIdentifier: Array[Byte] =
      if (identifier == null) null
      else Array.copyOf(identifier, identifier.length)

    def getKeyId: Int = keyId

    def getKeyType: String = keyType

    def getKey: Key = key

    def getParameters: Parameters = {
      if (key == null) return null
      key.getParameters
    }
  }

  @throws[GeneralSecurityException]
  private def addEntryToMap[P](fullPrimitive: Option[P], primitive: Option[P], key: Keyset.Key, primitives: collection.concurrent.TrieMap[PrimitiveSet.Prefix, List[PrimitiveSet.Entry[P]]]) = {
    val idRequirement: Option[Int] =
      if (key.getOutputPrefixType eq OutputPrefixType.RAW) None
      else Some(key.getKeyId)

    val keyObject = SerializationRegistry.parseKey(ProtoKeySerialization.create(key.getKeyData.getTypeUrl, key.getKeyData.getValue, key.getKeyData.getKeyMaterialType, key.getOutputPrefixType, idRequirement), InsecureSecretKeyAccess.get)
    val entry = new PrimitiveSet.Entry[P](fullPrimitive, primitive, CryptoFormat.getOutputPrefix(key), key.getStatus, key.getOutputPrefixType, key.getKeyId, key.getKeyData.getTypeUrl, keyObject)
    val list = mutable.ArrayBuffer.empty[PrimitiveSet.Entry[P]]
    list.append(entry)
    // Cannot use byte[] as keys in hash map, convert to Prefix wrapper class.
    val identifier = new PrimitiveSet.Prefix(entry.getIdentifier)
    val existing = primitives.put(identifier, list.toList)
    if (existing.isDefined) {
      val newList = mutable.ArrayBuffer.empty[PrimitiveSet.Entry[P]]
      newList.addAll(existing.get)
      newList.append(entry)
      primitives.put(identifier, newList.toList)
    }
    entry
  }

  /**
   * Creates a new mutable PrimitiveSet.
   *
   * @deprecated use {@link Builder} instead.
   */
  @deprecated def newPrimitiveSet[P](primitiveClass: Class[P]) = new PrimitiveSet[P](primitiveClass)

  private[PrimitiveSet] class Prefix private[PrimitiveSet](_prefix: Array[Byte]) extends Comparable[PrimitiveSet.Prefix] {
    final private val prefix: Array[Byte] = Array.copyOf(_prefix, _prefix.length)

    override def hashCode: Int = prefix.toSeq.hashCode()

    override def equals(o: Any): Boolean = {
      if (!o.isInstanceOf[PrimitiveSet.Prefix]) return false
      val other = o.asInstanceOf[PrimitiveSet.Prefix]
      prefix sameElements other.prefix
    }

    override def compareTo(o: PrimitiveSet.Prefix): Int = {
      if (prefix.length != o.prefix.length) return prefix.length - o.prefix.length
      var i = 0
      while (i < prefix.length) {
        if (prefix(i) != o.prefix(i)) return prefix(i) - o.prefix(i)
        i += 1
      }
      0
    }

    override def toString: String = Hex.encode(prefix)
  }

  /** Builds an immutable PrimitiveSet. This is the prefered way to construct a PrimitiveSet. */
  class Builder[P] private[PrimitiveSet](private val primitiveClass: Class[P]) {
    //this.annotations = MonitoringAnnotations.EMPTY;
    // primitives == null indicates that build has been called and the builder can't be used
    // anymore.
    private var primitives = collection.concurrent.TrieMap.empty[PrimitiveSet.Prefix, List[PrimitiveSet.Entry[P]]]
    private var primary: PrimitiveSet.Entry[P] = null

    //@CanIgnoreReturnValue
    //private MonitoringAnnotations annotations;
    @throws[GeneralSecurityException]
    private def addPrimitive(fullPrimitive: Option[P], primitive: Option[P], key: Keyset.Key, asPrimary: Boolean) = {
      if (primitives == null) throw new IllegalStateException("addPrimitive cannot be called after build")
      if ((fullPrimitive == null || fullPrimitive.isEmpty) && (primitive == null || primitive.isEmpty)) {
        throw new GeneralSecurityException("at least one of the `fullPrimitive` or `primitive` must be set")
      }
      if (key.getStatus ne KeyStatusType.ENABLED) throw new GeneralSecurityException("only ENABLED key is allowed")
      val entry = addEntryToMap(fullPrimitive, primitive, key, primitives)
      if (asPrimary) {
        if (this.primary != null) throw new IllegalStateException("you cannot set two primary primitives")
        this.primary = entry
      }
      this
    }

    @throws[GeneralSecurityException]
    private def addPrimitive(primitive: Option[P], key: Keyset.Key, asPrimary: Boolean) = {
      if (primitives == null) throw new IllegalStateException("addPrimitive cannot be called after build")
      if (primitive == null || primitive.isEmpty) throw new GeneralSecurityException("at least one of the `fullPrimitive` or `primitive` must be set")
      if (key.getStatus ne KeyStatusType.ENABLED) throw new GeneralSecurityException("only ENABLED key is allowed")
      val entry = addEntryToMap(None, primitive, key, primitives)
      if (asPrimary) {
        if (this.primary != null) throw new IllegalStateException("you cannot set two primary primitives")
        this.primary = entry
      }
      this
    }

    /* Adds a non-primary primitive.*/
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addPrimitive(primitive: Option[P], key: Keyset.Key): PrimitiveSet.Builder[P] = addPrimitive(primitive, key, false)

    /* Adds a non-primary primitive.*/
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addPrimitive(primitive: P, key: Keyset.Key): PrimitiveSet.Builder[P] = addPrimitive(Option(primitive), key, false)

    /**
     * Adds the primary primitive. This or addPrimaryFullPrimitiveAndOptionalPrimitive should be
     * called exactly once per PrimitiveSet.
     */
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addPrimaryPrimitive(primitive: Option[P], key: Keyset.Key): PrimitiveSet.Builder[P] = addPrimitive(primitive, key, true)

    /**
     * Adds the primary primitive. This or addPrimaryFullPrimitiveAndOptionalPrimitive should be
     * called exactly once per PrimitiveSet.
     */
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addPrimaryPrimitive(primitive: P, key: Keyset.Key): PrimitiveSet.Builder[P] = addPrimitive(Option(primitive), key, true)

    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addFullPrimitiveAndOptionalPrimitive(fullPrimitive: Option[P], primitive: Option[P], key: Keyset.Key): PrimitiveSet.Builder[P] =
      addPrimitive(fullPrimitive, primitive, key, false)

    /**
     * Adds the primary primitive and full primitive. This or addPrimaryPrimitive should be called
     * exactly once per PrimitiveSet.
     */
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def addPrimaryFullPrimitiveAndOptionalPrimitive(fullPrimitive: Option[P], primitive: Option[P], key: Keyset.Key): PrimitiveSet.Builder[P] =
      addPrimitive(fullPrimitive, primitive, key, true)

    @throws[GeneralSecurityException]
    def build: PrimitiveSet[P] = {
      if (primitives == null) throw new IllegalStateException("build cannot be called twice")
      // Note that we currently don't enforce that primary must be set.
      val output = new PrimitiveSet[P](primitives, Some(primary), primitiveClass)
      this.primitives = null
      output
    }
  }

  def newBuilder[P](primitiveClass: Class[P]) = new PrimitiveSet.Builder[P](primitiveClass)
}

/**
 * The primitives are stored in a hash map of (ciphertext prefix, list of primivies sharing the
 * prefix). This allows quickly retrieving the list of primitives sharing some particular prefix.
 * Because all RAW keys are using an empty prefix, this also quickly allows retrieving them.
 *
 * Creates an immutable PrimitiveSet. It is used by the Builder.
 * */
final class PrimitiveSet[P] (private val primitives: collection.concurrent.TrieMap[PrimitiveSet.Prefix, List[PrimitiveSet.Entry[P]]],
                             private var primary: Option[PrimitiveSet.Entry[P]],
                             private val primitiveClass: Class[P]) {

  private var isMutable = false

  /** Returns the entry with the primary primitive. */
  def getPrimary: Option[PrimitiveSet.Entry[P]] = primary


  /** @return all primitives using RAW prefix. */
  def getRawPrimitives: List[PrimitiveSet.Entry[P]] = getPrimitive(CryptoFormat.RAW_PREFIX)

  /** @return the entries with primitive identifed by {@code identifier}. */
  def getPrimitive(identifier: Array[Byte]): List[PrimitiveSet.Entry[P]] = {
    val found = primitives.get(new PrimitiveSet.Prefix(identifier))
    if (found != null && found.isDefined) found.get
    else List.empty[PrimitiveSet.Entry[P]]
  }

  /** @return all primitives */
  def getAll: Seq[List[PrimitiveSet.Entry[P]]] = primitives.values.toSeq

  def this(primitiveClass: Class[P]) = {
    this(collection.concurrent.TrieMap.empty, None, primitiveClass)
    this.isMutable = true
  }

  /**
   * Sets given Entry {@code primary} as the primary one.
   *
   * @throws IllegalStateException if object has been created by the {@link Builder}.
   * @deprecated use {@link Builder.addPrimaryPrimitive} instead.
   */
  @deprecated /* Deprecation under consideration */
  def setPrimary(primary: PrimitiveSet.Entry[P]): Unit = {
    if (!isMutable) throw new IllegalStateException("setPrimary cannot be called on an immutable primitive set")
    if (primary == null) throw new IllegalArgumentException("the primary entry must be non-null")
    if (primary.getStatus ne KeyStatusType.ENABLED) throw new IllegalArgumentException("the primary entry has to be ENABLED")
    val entries = getPrimitive(primary.getIdentifier)
    if (entries.isEmpty) throw new IllegalArgumentException("the primary entry cannot be set to an entry which is not held by this primitive set")
    this.primary = Some(primary)
  }

  def getPrimitiveClass: Class[P] = primitiveClass
}