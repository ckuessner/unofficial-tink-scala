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

import com.google.crypto.tink
import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.internal.{ProtoKeySerialization, ProtoParametersSerialization, SerializationRegistry, TinkBugException}
import com.google.crypto.tink.proto.*
import com.google.crypto.tink.tinkkey.internal.{InternalKeyHandle, ProtoKey}
import com.google.crypto.tink.tinkkey.{KeyAccess, KeyHandle}

import java.io.IOException
import java.security.GeneralSecurityException
import java.util
import java.util.Collections
import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/**
 * A KeysetHandle provides abstracted access to {@link Keyset}, to limit the exposure of actual
 * protocol buffers that hold sensitive key material.
 *
 * <p>This class allows reading and writing encrypted keysets. Users that want to read or write can
 * use the restricted API {@link CleartextKeysetHandle}.
 *
 * @since 1.0.0
 */
object KeysetHandle {
  /**
   * Used to create new {@code KeysetHandle} objects.
   *
   * <p>A builder can be used to create a new {@code KeysetHandle} object. To create a builder with
   * an empty keyset, one calls {@code KeysetHandle.newBuilder();}. To create a builder from an
   * existing keyset, one calls {@code KeysetHandle.newBuilder(keyset);}.
   *
   * <p>To add a new key to a {@code Builder}, one calls {@link # addEntry} with a KeysetEntry
   * object. Such objects can be created
   *
   * <ul>
   * <li>From a named {@link Parameters} with {@link
 * KeysetHandle#generateEntryFromParametersName},
   * <li>From a {@link Parameters} object, with {@link KeysetHandle# generateEntryFromParameters},
   * <li>By importing an existing key, with {@link KeysetHandle# importKey}
   * </ul>
   *
   * . 7
   *
   * <p>All these functions return a {@code KeysetBuilder.Entry}. It is necessary to assign an ID to
   * a new entry by calling one of {@link Entry# withFixedId} or {@link Entry# withRandomId}. The
   * exception is when an existing key which has an id requirement is imported (in which case the
   * required ID is used).
   *
   * <p>It is possible to set the status of an entry by calling {@link Entry# setStatus}. The Status
   * defaults to {@code ENABLED}.
   *
   * <p>It is possible to set whether an entry is the primary by calling {@link Entry# makePrimary}.
   * The user must ensure that once {@link # build} is called, a primary has been set.
   */
  object Builder {
    private object KeyIdStrategy {
      private[KeysetHandle] val RANDOM_ID = new Builder.KeyIdStrategy()

      private[KeysetHandle] def randomId = RANDOM_ID

      private[KeysetHandle] def fixedId(id: Int) = new Builder.KeyIdStrategy(id)
    }

    private[KeysetHandle] class KeyIdStrategy private[KeysetHandle](val fixedId: Int = 0) {
      private[KeysetHandle] def getFixedId = fixedId
    }

    /**
     * One entry, representing a single key, in a Keyset.Builder.
     *
     * <p>This is the analogue of {@link Keyset.Entry} for a builder.
     *
     * <p>Users will have to ensure that each entry has an ID, and one entry is a primary. See
     * {@link KeysetHandle.Builder# build} for details).
     */
    final class Entry {
      // When "build" is called, for exactly one entry "isPrimary" needs to be set, and it should
      // be enabled.
      private[KeysetHandle] var _isPrimary = false
      // Set to ENABLED by default.
      private[KeysetHandle] var keyStatus = KeyStatus.ENABLED
      // Exactly one of key and parameters will be non-null (set in the constructor).
      /*@Nullable*/ final private[KeysetHandle] var key: Key = null
      /*@Nullable*/ final private[KeysetHandle] var parameters: Parameters = null
      // strategy must be non-null when the keyset is built.
      private[KeysetHandle] var strategy: Builder.KeyIdStrategy = null
      // The Builder which this Entry is part of. Each entry can be part of only one builder.
      // When constructing a new entry, it is not part of any builder.
      /*@Nullable*/ private[KeysetHandle] var builder: KeysetHandle.Builder = null

      def this(key: Key) = {
        this()
        this.key = key
        this.parameters = null
      }

      def this(parameters: Parameters) = {
        this()
        this.key = null
        this.parameters = parameters
      }

      /**
       * Marks that this entry is the primary key.
       *
       * <p>Other entries in the same keyset will be marked as non-primary if this Entry has already
       * been added to a builder, otherwise they will marked as non-primary once this entry is added
       * to a builder.
       */
      //@CanIgnoreReturnValue
      def makePrimary: Builder.Entry = {
        if (builder != null) builder.clearPrimary()
        this._isPrimary = true
        this
      }

      def isPrimary: Boolean = this._isPrimary

      /** Sets the status of this entry. */
      //@CanIgnoreReturnValue
      def setStatus(status: KeyStatus): Builder.Entry = {
        keyStatus = status
        this
      }

      /** Returns the status of this entry. */
      def getStatus: KeyStatus = keyStatus

      /** Tells Tink to assign a fixed id when this keyset is built. */
      //@CanIgnoreReturnValue
      def withFixedId(id: Int): Builder.Entry = {
        this.strategy = KeyIdStrategy.fixedId(id)
        this
      }

      /**
       * Tells Tink to assign an unused uniform random id when this keyset is built.
       *
       * <p>Using {@code withRandomId} is invalid for an entry with an imported or preexisting key,
       * which has an ID requirement.
       *
       * <p>If an entry is marked as {@code withRandomId}, all subsequent entries also need to be
       * marked with {@code withRandomId}, or else calling {@code build()} will fail.
       */
      //@CanIgnoreReturnValue
      def withRandomId: Builder.Entry = {
        this.strategy = KeyIdStrategy.randomId
        this
      }
    }

    @throws[GeneralSecurityException]
    private def checkIdAssignments(entries: mutable.ListBuffer[Builder.Entry]): Unit = {
      // We want "withRandomId"-entries after fixed id, as otherwise it might be that we randomly
      // pick a number which is later specified as "withFixedId". Looking forward is deemed too
      // complicated, especially if in the future we want different strategies (such as
      // "withNextId").
      for (i <- 0 until entries.size - 1) {
        if ((entries(i).strategy == KeyIdStrategy.RANDOM_ID) && (entries(i + 1).strategy != KeyIdStrategy.RANDOM_ID)) {
          throw new GeneralSecurityException("Entries with 'withRandomId()' may only be followed by other entries with" + " 'withRandomId()'.")
        }
      }
    }

    private def randomIdNotInSet(ids: mutable.HashSet[Int]) = {
      var id = 0
      while (id == 0 || ids.contains(id)) id = com.google.crypto.tink.internal.Util.randKeyId
      id
    }

    @throws[GeneralSecurityException]
    private def createKeyFromParameters(parameters: Parameters, id: Int, keyStatusType: KeyStatusType) = {
      val keyTemplate = parameters.toKeyTemplate
      val keyData = Registry.newKeyData(keyTemplate)
      Keyset.Key.newBuilder.setKeyId(id).setStatus(keyStatusType).setKeyData(keyData).setOutputPrefixType(keyTemplate.getProto.getOutputPrefixType).build
    }

    @throws[GeneralSecurityException]
    private def getNextIdFromBuilderEntry(builderEntry: Builder.Entry, idsSoFar: mutable.HashSet[Int]) = {
      var id = 0
      if (builderEntry.strategy == null) throw new GeneralSecurityException("No ID was set (with withFixedId or withRandomId)")
      if (builderEntry.strategy == KeyIdStrategy.RANDOM_ID) id = randomIdNotInSet(idsSoFar)
      else id = builderEntry.strategy.getFixedId
      id
    }

    @throws[GeneralSecurityException]
    private def createKeysetKeyFromBuilderEntry(builderEntry: Builder.Entry, id: Int) = if (builderEntry.key == null) createKeyFromParameters(builderEntry.parameters, id, serializeStatus(builderEntry.getStatus))
    else {
      val serializedKey = SerializationRegistry.serializeKey(builderEntry.key, classOf[ProtoKeySerialization], InsecureSecretKeyAccess.get)
      val idRequirement = serializedKey.getIdRequirement
      if (idRequirement != null && idRequirement.isDefined && (idRequirement.get != id)) throw new GeneralSecurityException("Wrong ID set for key with ID requirement")
      toKeysetKey(id, serializeStatus(builderEntry.getStatus), serializedKey)
    }
  }

  final class Builder {
    final private val entries: ListBuffer[Builder.Entry] = mutable.ListBuffer.empty[Builder.Entry]

    private def clearPrimary(): Unit = {
      for (entry <- entries) {
        entry._isPrimary = false
      }
    }

    /** Adds an entry to a keyset */
    //@CanIgnoreReturnValue
    def addEntry(entry: Builder.Entry): KeysetHandle.Builder = {
      if (entry.builder != null) throw new IllegalStateException("Entry has already been added to a KeysetHandle.Builder")
      if (entry.isPrimary) clearPrimary()
      entry.builder = this
      entries.append(entry)
      this
    }

    /** Returns the number of entries in this builder. */
    def size: Int = entries.size

    /**
     * Returns the entry at index i, 0 <= i < size().
     *
     * @throws IndexOutOfBoundsException if i < 0 or i >= size();
     */
    def getAt(i: Int): Builder.Entry = entries(i)

    /**
     * Removes the entry at index {@code i} and returns that entry. Shifts any subsequent entries to
     * the left (subtracts one from their indices).
     *
     * @deprecated Use {@link # deleteAt} or {@link # getAt} instead.
     */
    //@CanIgnoreReturnValue
    @deprecated def removeAt(i: Int): Builder.Entry = entries.remove(i)

    /**
     * Deletes the entry at index {@code i}. Shifts any subsequent entries to the left (subtracts
     * one from their indices).
     */
    //@CanIgnoreReturnValue
    def deleteAt(i: Int): KeysetHandle.Builder = {
      entries.remove(i)
      this
    }

    /**
     * Creates a new {@code KeysetHandle}.
     *
     * <p>Throws a {@code GeneralSecurityException} if one of the following holds
     *
     * <ul>
     * <li>No entry was marked as primary
     * <li>There is an entry in which the ID has not been set and which did not have a predefined
     * ID (see {@link Builder.Entry}).
     * <li>There is a {@code withRandomId}-entry which is followed by a non {@code
     * withRandomId}-entry
     * <li>There are two entries with the same {@code withFixedId} (including pre-existing keys
     * and imported keys which have an id requirement).
     * </ul>
     */
    @throws[GeneralSecurityException]
    def build: KeysetHandle = {
      val keysetBuilder = Keyset.newBuilder
      var primaryId: Int | Null = null
      Builder.checkIdAssignments(entries)
      val idsSoFar = mutable.HashSet.empty[Int]
      for (builderEntry <- entries) {
        if (builderEntry.keyStatus == null) throw new GeneralSecurityException("Key Status not set.")
        val id = Builder.getNextIdFromBuilderEntry(builderEntry, idsSoFar)
        if (idsSoFar.contains(id)) throw new GeneralSecurityException("Id " + id + " is used twice in the keyset")
        idsSoFar.add(id)
        val keysetKey = Builder.createKeysetKeyFromBuilderEntry(builderEntry, id)
        keysetBuilder.addKey(keysetKey)
        if (builderEntry.isPrimary) {
          if (primaryId != null) throw new GeneralSecurityException("Two primaries were set")
          primaryId = id
        }
      }
      primaryId match {
        case null => throw new GeneralSecurityException("No primary was set")
        case primaryId: Int =>
          keysetBuilder.setPrimaryKeyId(primaryId)
          KeysetHandle.fromKeyset(keysetBuilder.build)
      }
    }
  }

  /**
   * Represents a single entry in a keyset.
   *
   * <p>An entry in a keyset consists of a key, its ID, and the {@link KeyStatus}. In addition,
   * there is one key marked as a primary.
   *
   * <p>The ID should be considered unique (though currently Tink still accepts keysets with
   * repeated IDs). The {@code KeyStatus} tells Tink whether the key should still be used or not.
   * There should always be exactly one key which is marked as a primary, however, at the moment
   * Tink still accepts keysets which have none. This will be changed in the future.
   */
  @Alpha
  final class Entry private[KeysetHandle](private val key: Key, private val keyStatus: KeyStatus, private val id: Int, private val _isPrimary: Boolean) {
    /**
     * May return an internal class {@link com.google.crypto.tink.internal.LegacyProtoKey} in case
     * there is no implementation of the corresponding key class yet.
     */
    def getKey: Key = key

    def getStatus: KeyStatus = keyStatus

    def getId: Int = id

    /**
     * Guaranteed to be true in exactly one entry.
     *
     * <p>Note: currently this may be false for all entries, since it is possible that keysets are
     * parsed without a primary. In the future, such keysets will be rejected when the keyset is
     * parsed.
     */
    def isPrimary: Boolean = _isPrimary
  }

  @throws[GeneralSecurityException]
  private def parseStatus(in: KeyStatusType) = in match {
    case KeyStatusType.ENABLED =>
      KeyStatus.ENABLED
    case KeyStatusType.DISABLED =>
      KeyStatus.DISABLED
    case KeyStatusType.DESTROYED =>
      KeyStatus.DESTROYED
    case _ =>
      throw new GeneralSecurityException("Unknown key status")
  }

  private def serializeStatus(in: KeyStatus): KeyStatusType = {
    if (KeyStatus.ENABLED == in) return KeyStatusType.ENABLED
    if (KeyStatus.DISABLED == in) return KeyStatusType.DISABLED
    if (KeyStatus.DESTROYED == in) return KeyStatusType.DESTROYED
    throw new IllegalStateException("Unknown key status")
  }

  private def toKeysetKey(id: Int, status: KeyStatusType, protoKeySerialization: ProtoKeySerialization) = Keyset.Key.newBuilder.setKeyData(KeyData.newBuilder.setTypeUrl(protoKeySerialization.getTypeUrl).setValue(protoKeySerialization.getValue).setKeyMaterialType(protoKeySerialization.getKeyMaterialType).build).setStatus(status).setKeyId(id).setOutputPrefixType(protoKeySerialization.getOutputPrefixType).build

  /**
   * Returns an immutable list of key objects for this keyset.
   *
   * <p>If a status is unparseable or parsing of a key fails, there will be "null" in the
   * corresponding entry.
   */
  private def getEntriesFromKeyset(keyset: Keyset) = {
    val result = new util.ArrayList[KeysetHandle.Entry](keyset.getKeyCount)
    for (protoKey <- keyset.keys) {
      val id = protoKey.getKeyId
      val protoKeySerialization = toProtoKeySerialization(protoKey)
      try {
        val key = SerializationRegistry.parseKey(protoKeySerialization, InsecureSecretKeyAccess.get)
        result.add(new KeysetHandle.Entry(key, parseStatus(protoKey.getStatus), id, id == keyset.getPrimaryKeyId))
      } catch {
        case e: GeneralSecurityException =>
          result.add(null)
      }
    }
    Collections.unmodifiableList(result)
  }

  private def toProtoKeySerialization(protoKey: Keyset.Key) = {
    val id = protoKey.getKeyId
    //@Nullable
    val idRequirement =
      if (protoKey.getOutputPrefixType eq OutputPrefixType.RAW) None
      else Some(id)

    try {
      ProtoKeySerialization.create(protoKey.getKeyData.getTypeUrl, protoKey.getKeyData.getValue, protoKey.getKeyData.getKeyMaterialType, protoKey.getOutputPrefixType, idRequirement)
    } catch {
      case e: GeneralSecurityException =>

        // Cannot happen -- this only happens if the idRequirement doesn't match OutputPrefixType
        throw new TinkBugException("Creating a protokey serialization failed", e)
    }
  }

  /**
   * Creates a new entry with a fixed key.
   *
   * <p>If the Key has an IdRequirement, the default will be fixed to this ID. Otherwise, the user
   * has to specify the ID to be used and call one of {@code withFixedId(i)} or {@code
   * withRandomId()} on the returned entry.
   */
  def importKey(key: Key): Builder.Entry = {
    val importedEntry = new Builder.Entry(key)
    val requirement = key.getIdRequirement
    if (requirement != null && requirement.isDefined) importedEntry.withFixedId(requirement.get)
    importedEntry
  }

  /**
   * Creates a new entry with Status "ENABLED" and a new key created from the parameters. No ID is
   * set.
   */
  def generateEntryFromParameters(parameters: Parameters) = new Builder.Entry(parameters)

  /**
   * @return a new {@link KeysetHandle} from a {@code keyset}.
   * @throws GeneralSecurityException if the keyset is null or empty.
   */
  @throws[GeneralSecurityException]
  private[tink] def fromKeyset(keyset: Keyset) = {
    assertEnoughKeyMaterial(keyset)
    val entries = getEntriesFromKeyset(keyset)
    new KeysetHandle(keyset, entries)
  }

  /** Creates a new builder. */
  def newBuilder = new KeysetHandle.Builder

  /** Creates a new builder, initially containing all entries from {@code handle}. */
  def newBuilder(handle: KeysetHandle): KeysetHandle.Builder = {
    val builder = new KeysetHandle.Builder
    for (i <- 0 until handle.size) {
      val entry = handle.entryByIndex(i)
      val builderEntry = importKey(entry.getKey).withFixedId(entry.getId)
      builderEntry.setStatus(entry.getStatus)
      if (entry.isPrimary) builderEntry.makePrimary
      builder.addEntry(builderEntry)
    }
    builder
  }

  /**
   * Generates a new {@link KeysetHandle} that contains a single fresh key generated according to
   * {@code keyTemplate}.
   *
   * @throws GeneralSecurityException if the key template is invalid.
   */
  @throws[GeneralSecurityException]
  def generateNew(keyTemplate: tink.KeyTemplate): KeysetHandle = {
    val protoParametersSerialization = ProtoParametersSerialization.create(keyTemplate.getProto)
    val parameters = protoParametersSerialization.toParametersPojo
    KeysetHandle.newBuilder.addEntry(KeysetHandle.generateEntryFromParameters(parameters).makePrimary.withRandomId).build
  }

  /**
   * Returns a {@code KeysetHandle} that contains the single {@code KeyHandle} passed as input.
   *
   * @deprecated Use {@link KeysetHandle.Builder.addEntry} instead.
   */
  @deprecated
  @throws[GeneralSecurityException]
  def createFromKey(keyHandle: KeyHandle, access: KeyAccess): KeysetHandle = {
    val km = KeysetManager.withEmptyKeyset.add(keyHandle)
    km.setPrimary(km.getKeysetHandle.getKeysetInfo.getKeyInfo(0).getKeyId)
    km.getKeysetHandle
  }

  /**
   * Tries to create a {@link KeysetHandle} from a keyset, obtained via {@code reader}, which
   * contains no secret key material.
   *
   * <p>This can be used to load public keysets or envelope encryption keysets. Users that need to
   * load cleartext keysets can use {@link CleartextKeysetHandle}.
   *
   * @return a new {@link KeysetHandle} from {@code serialized} that is a serialized {@link Keyset}
   * @throws GeneralSecurityException if the keyset is invalid
   */
  @SuppressWarnings(Array("UnusedException"))
  @throws[GeneralSecurityException]
  @throws[IOException]
  def readNoSecret(reader: KeysetReader): KeysetHandle = try {
    val keyset = reader.read
    assertNoSecretKeyMaterial(keyset)
    KeysetHandle.fromKeyset(keyset)
  } catch {
    case e: Exception =>

      // Do not propagate InvalidProtocolBufferException to guarantee no key material is leaked
      throw new GeneralSecurityException("invalid keyset")
  }

  @throws[GeneralSecurityException]
  private def createPublicKeyData(privateKeyData: KeyData) = {
    if (privateKeyData.getKeyMaterialType ne KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) throw new GeneralSecurityException("The keyset contains a non-private key")
    val publicKeyData = Registry.getPublicKeyData(privateKeyData.getTypeUrl, privateKeyData.getValue)
    validate(publicKeyData)
    publicKeyData
  }

  @SuppressWarnings(Array("deprecation"))
  @throws[GeneralSecurityException]
  private def validate(keyData: KeyData): Unit = {
    // This will throw GeneralSecurityException if the keyData is invalid.
    val unused: Object = Registry.getPrimitive(keyData)
    print(unused)
  }

  /**
   * Validates that {@code keyset} doesn't contain any secret key material.
   *
   * @throws GeneralSecurityException if {@code keyset} contains secret key material.
   */
  @throws[GeneralSecurityException]
  private def assertNoSecretKeyMaterial(keyset: Keyset): Unit = {
    for (key <- keyset.keys) {
      if ((key.getKeyData.getKeyMaterialType eq KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL) || (key.getKeyData.getKeyMaterialType eq KeyData.KeyMaterialType.SYMMETRIC) || (key.getKeyData.getKeyMaterialType eq KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)) throw new GeneralSecurityException(String.format("keyset contains key material of type %s for type url %s", key.getKeyData.getKeyMaterialType.name, key.getKeyData.getTypeUrl))
    }
  }

  /**
   * Validates that a keyset handle contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException if the validation fails
   */
  @throws[GeneralSecurityException]
  private def assertEnoughKeyMaterial(keyset: Keyset): Unit = {
    if (keyset == null || keyset.getKeyCount <= 0) throw new GeneralSecurityException("empty keyset")
  }

  /**
   * Validates that an encrypted keyset contains enough key material to build a keyset on.
   *
   * @throws GeneralSecurityException if the validation fails
   */
  @throws[GeneralSecurityException]
  private def assertEnoughEncryptedKeyMaterial(keyset: EncryptedKeyset): Unit = {
    if (keyset == null || keyset.getEncryptedKeyset.size == 0) throw new GeneralSecurityException("empty keyset")
  }

  //@Nullable
  @throws[GeneralSecurityException]
  private def getLegacyPrimitive[B](key: Keyset.Key, inputPrimitiveClassObject: Class[B]): Option[B] = {
    try {
      Option(Registry.getPrimitive(key.getKeyData, inputPrimitiveClassObject))
    } catch {
      case e: GeneralSecurityException =>
        if (e.getMessage.contains("No key manager found for key type ") || e.getMessage.contains(" not supported by key manager of type ")) {
          // Ignoring because the key may not have a corresponding legacy key manager.
          return None
        }
        // Otherwise the error is likely legit. Do not swallow.
        throw e
    }
  }
}

final class KeysetHandle private(private val keyset: Keyset,
                                 private val entries: util.List[KeysetHandle.Entry]) /* Contains all entries; but if either parsing the status or the key failed, contains null.*/ {
  //this.annotations = MonitoringAnnotations.EMPTY;
  private def entryByIndex(i: Int) = {
    if (entries.get(i) == null) {
      // This may happen if a keyset without status makes it here; or if a key has a parser
      // registered but parsing fails. We should reject such keysets earlier instead.
      throw new IllegalStateException("Keyset-Entry at position i has wrong status or key parsing failed")
    }
    entries.get(i)
  }

  /**
   * @return the actual keyset data.
   */
  private[tink] def getKeyset = keyset

  /**
   * Returns the unique entry where isPrimary() = true and getStatus() = ENABLED.
   *
   * <p>Note: currently this may throw IllegalStateException, since it is possible that keysets are
   * parsed without a primary. In the future, such keysets will be rejected when the keyset is
   * parsed.
   */
  def getPrimary: KeysetHandle.Entry = {
    var i = 0
    while (i < keyset.getKeyCount) {
      if (keyset.getKey(i).getKeyId == keyset.getPrimaryKeyId) {
        val result = entryByIndex(i)
        if (result.getStatus ne KeyStatus.ENABLED) throw new IllegalStateException("Keyset has primary which isn't enabled")
        return result
      }
      i += 1
    }
    throw new IllegalStateException("Keyset has no primary")
  }

  /** Returns the size of this keyset. */
  def size: Int = keyset.getKeyCount

  /**
   * Returns the entry at index i. The order is preserved and depends on the order at which the
   * entries were inserted when the KeysetHandle was built.
   *
   * <p>Currently, this may throw "IllegalStateException" in case the status entry of the Key in the
   * keyset was wrongly set. In the future, Tink will throw at parsing time in this case.
   *
   * @throws IndexOutOfBoundsException if i < 0 or i >= size();
   */
  def getAt(i: Int): KeysetHandle.Entry = {
    if (i < 0 || i >= size) throw new IndexOutOfBoundsException("Invalid index " + i + " for keyset of size " + size)
    entryByIndex(i)
  }

  /**
   * Returns the keyset data as a list of {@link KeyHandle}s.
   *
   * @deprecated Use {@link # size} and {@link # getAt} instead.
   */
  @deprecated /* Deprecation under consideration */ def getKeys: util.List[KeyHandle] = {
    val result = new util.ArrayList[KeyHandle]
    for (key <- keyset.keys) {
      val keyData = key.getKeyData
      result.add(new InternalKeyHandle(new ProtoKey(keyData, tink.KeyTemplate.fromProto(key.getOutputPrefixType)), key.getStatus, key.getKeyId))
    }
    Collections.unmodifiableList(result)
  }

  /**
   * @return the {@link com.google.crypto.tink.proto.KeysetInfo} that doesn't contain actual key
   *         material.
   */
  def getKeysetInfo: KeysetInfo = Util.getKeysetInfo(keyset)

  /**
   * If the managed keyset contains private keys, returns a {@link KeysetHandle} of the public keys.
   *
   * @throws GenernalSecurityException if the managed keyset is null or if it contains any
   *                                   non-private keys.
   */
  @throws[GeneralSecurityException]
  def getPublicKeysetHandle: KeysetHandle = {
    if (keyset == null) throw new GeneralSecurityException("cleartext keyset is not available")
    val keysetBuilder = Keyset.newBuilder
    for (key <- keyset.keys) {
      val keyData = KeysetHandle.createPublicKeyData(key.getKeyData)
      keysetBuilder.addKey(key.toBuilder.setKeyData(keyData).build)
    }
    keysetBuilder.setPrimaryKeyId(keyset.getPrimaryKeyId)
    KeysetHandle.fromKeyset(keysetBuilder.build)
  }

  /**
   * Extracts and returns the string representation of the [[
   * com.google.crypto.tink.proto.KeysetInfo]] of the managed keyset.
   */
  // main purpose of toString is for debugging
  override def toString: String = getKeysetInfo.toString

  /** Allows us to have a name {@code B} for the base primitive. */
  @throws[GeneralSecurityException]
  private def getPrimitiveWithKnownInputPrimitive[B, P](classObject: Class[P], inputPrimitiveClassObject: Class[B]) = {
    Util.validateKeyset(keyset)
    val builder = PrimitiveSet.newBuilder(inputPrimitiveClassObject)
    for (i <- 0 until size) {
      val protoKey = keyset.getKey(i)
      if (protoKey.getStatus == KeyStatusType.ENABLED) {
        /*@Nullable*/ val primitive: Option[B] = KeysetHandle.getLegacyPrimitive(protoKey, inputPrimitiveClassObject)
        /*@Nullable*/ var fullPrimitive: Option[B] = None
        // Entries.get(i) may be null (if the status is invalid in the proto, or parsing failed.
        if (entries.get(i) != null) fullPrimitive = getFullPrimitive(entries.get(i).getKey, inputPrimitiveClassObject)
        if (protoKey.getKeyId == keyset.getPrimaryKeyId) builder.addPrimaryFullPrimitiveAndOptionalPrimitive(fullPrimitive, primitive, protoKey)
        else builder.addFullPrimitiveAndOptionalPrimitive(fullPrimitive, primitive, protoKey)
      }
    }
    Registry.wrap(builder.build, classObject)
  }

  /**
   * Returns a primitive from this keyset, using the global registry to create resources creating
   * the primitive.
   */
  @throws[GeneralSecurityException]
  def getPrimitive[P](targetClassObject: Class[P]) = {
    val inputPrimitiveClassObject = Registry.getInputPrimitive(targetClassObject)
    if (inputPrimitiveClassObject == null) throw new GeneralSecurityException("No wrapper found for " + targetClassObject.getName)
    getPrimitiveWithKnownInputPrimitive(targetClassObject, inputPrimitiveClassObject)
  }

  /**
   * Searches the keyset to find the primary key of this {@code KeysetHandle}, and returns the key
   * wrapped in a {@code KeyHandle}.
   *
   * @deprecated Use {@link # getPrimary} instead.
   */
  @deprecated /* Deprecation under consideration */
  @throws[GeneralSecurityException]
  def primaryKey: KeyHandle = {
    val primaryKeyId = keyset.getPrimaryKeyId
    keyset.keys
      .find(key => key.getKeyId == primaryKeyId)
      .map(key => {
        new InternalKeyHandle(new ProtoKey(key.getKeyData, tink.KeyTemplate.fromProto(key.getOutputPrefixType)), key.getStatus, key.getKeyId)
      }) match {
      case Some(value) => value
      case None => throw new GeneralSecurityException("No primary key found in keyset.")
    }
  }

  //@Nullable
  @throws[GeneralSecurityException]
  private def getFullPrimitive[B](key: Key, inputPrimitiveClassObject: Class[B]): Option[B] =
    try {
      Some(Registry.getFullPrimitive(key, inputPrimitiveClassObject))
    } catch {
      case e: GeneralSecurityException =>
        // Ignoring because the key may not yet have a corresponding class.
        // TODO(lizatretyakova): stop ignoring when all key classes are migrated from protos.
        None
    }
}