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

import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.internal.KeyTypeManager.KeyFactory
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{KeyData, KeyProto}

import java.io.{IOException, InputStream}
import java.security.GeneralSecurityException
import scala.collection.mutable

/**
 * An object which collects all the operations which one can do on for a single key type, identified
 * by a single KeyProto.
 *
 * <p>A KeyTypeManager manages all the operations one can do on a given KeyProto. This includes
 * generating primitives, generating keys (if applicable), parsing and validating keys and key
 * formats. This object is meant to be implemented, i.e., one should use it via the {@link
 * Registry}, and not directly.
 *
 * <p>In order to implement a new key manager, one should subclass this class, setting the type
 * parameter to the proto of the corresponding key (e.g., subclass {@code
 * KeyTypeManager<AesGcmKey>}).
 *
 * <p>For each primitive the key manager should implement, one needs to add an argument to the
 * constructor. The type of it should be a {@code PrimitiveFactory<PrimitiveT, KeyT>}, an object
 * which knows how to produce primitives.
 *
 * <p>If the key manager can create new keys, one also needs to implement the method {@code
 * #keyFactory}. In this case it needs to return an object of type {@code KeyFactory<KeyFormatProto,
 * KeyProtoT>}, where one has to specify a proto for the key format as well.
 *
 * <p>This should not be used by Tink users outside of Google, since we first want to change it such
 * that it can be independent of the protobuf library.
 */
@Alpha
object KeyTypeManager {
  /**
   * A {@code KeyFactory} creates new keys from a given KeyFormat.
   *
   * <p>A KeyFactory implements all the methods which are required if a KeyTypeManager should also
   * be able to generate keys. In particular, in this case it needs to have some KeyFormat protocol
   * buffer which can be validated, parsed, and from which a key can be generated.
   */
  object KeyFactory {
    /**
     * A container that contains key type and other information that form key templates supported
     * by this factory.
     */
    final class KeyFormat[KeyProtoT <: KeyProto](val outputPrefixType: KeyTemplate.OutputPrefixType) {
    }

    /**
     * Reads {@code output.length} number of bytes of (pseudo)randomness from the {@code input}
     * stream into the provided {@code output} buffer.
     *
     * Note that this method will not close the {@code input} stream.
     *
     * @throws GeneralSecurityException when not enough randomness was provided in the {@code input}
     *                                  stream.
     */
    @throws[IOException]
    @throws[GeneralSecurityException]
    private[tink] def readFully(input: InputStream, output: Array[Byte]): Unit = {
      val len = output.length
      var read = 0
      var readTotal = 0
      while (readTotal < len) {
        read = input.read(output, readTotal, len - readTotal)
        if (read == -1) throw new GeneralSecurityException("Not enough pseudorandomness provided")
        readTotal += read
      }
    }
  }

  abstract class KeyFactory[KeyProtoT <: KeyProto] {
    /** Creates a new key from a given format. */
    @throws[GeneralSecurityException]
    def createKey: KeyProtoT

    /**
     * Derives a new key from a given format, using the given {@code pseudoRandomness}.
     *
     * <p>Implementations need to note that the given paramter {@code pseudoRandomness} may only
     * produce a finite amount of randomness. Hence, proper implementations will first obtain all
     * the pseudorandom bytes needed; and only after produce the key.
     *
     * <p>While {@link validateKeyFormat} is called before this method will be called,
     * implementations must check the version of the given {@code keyFormat}, as {@link
 * validateKeyFormat} is also called from {@link createKey}.
     *
     * <p>Not every KeyTypeManager needs to implement this; if not implemented a {@link
 * GeneralSecurityException} will be thrown.
     */
    @throws[GeneralSecurityException]
    def deriveKey(pseudoRandomness: InputStream): KeyProtoT = {
      throw new GeneralSecurityException("deriveKey not implemented by " + this.getClass)
    }

    /**
     * Returns supported key formats and their names.
     *
     * @throws GeneralSecurityException Key type managers can throw GeneralSecurityException when
     *                                  their key formats depend on other key formats that were not registered.
     */
    @throws[GeneralSecurityException]
    def keyFormats: Map[String, KeyFactory.KeyFormat[KeyProtoT]] = Map.empty
  }
}

/**
 * Constructs a new KeyTypeManager.
 *
 * <p>Takes an arbitrary number of [[PrimitiveFactory]] objects as input. These will be used
 * and provided via [[getPrimitive]] to the user.
 *
 * @throws IllegalArgumentException if two of the passed in factories produce primitives of the
 *                                  same class.
 */
@Alpha abstract class KeyTypeManager[KeyProtoT <: KeyProto] @SafeVarargs protected(private val clazz: Class[KeyProtoT], factoriesArg: PrimitiveFactory[?, KeyProtoT]*) {
  final private val firstPrimitiveClass: Class[?] =
    if (factoriesArg.nonEmpty) factoriesArg(0).getPrimitiveClass
    else classOf[Void]

  final private val factories: Map[Class[?], PrimitiveFactory[?, KeyProtoT]] = {
    val factoriesMap = mutable.Map.empty[Class[?], PrimitiveFactory[?, KeyProtoT]]
    for (factory <- factoriesArg) {
      if (factoriesMap.contains(factory.getPrimitiveClass)) throw new IllegalArgumentException("KeyTypeManager constructed with duplicate factories for primitive " + factory.getPrimitiveClass.getCanonicalName)
      factoriesMap.put(factory.getPrimitiveClass, factory)
    }

    factoriesMap.toMap
  }


  /** Returns the class corresponding to the key protobuffer. */
  final def getKeyClass: Class[KeyProtoT] = clazz

  /** Returns the type URL that identifies the key type of keys managed by this KeyManager. */
  def getKeyType: String

  /** Returns the {@link KeyMaterialType} for this proto. */
  def keyMaterialType: KeyData.KeyMaterialType

  /**
   * Checks if the given {@code keyProto} is a valid key.
   *
   * @throws GeneralSecurityException if the passed {@code keyProto} is not valid in any way.
   */
  @throws[GeneralSecurityException]
  def validateKey(keyProto: KeyProtoT): Unit

  /**
   * Creates the requested primitive.
   *
   * @throws java.lang.IllegalArgumentException if the given {@code primitiveClass} is not supported
   *                                            (i.e., not returned by {@link # supportedPrimitives}.
   * @throws GeneralSecurityException           if the underlying factory throws a GeneralSecurityException
   *                                            creating the primitive.
   */
  @throws[GeneralSecurityException]
  final def getPrimitive[P](key: KeyProtoT, primitiveClass: Class[P]): P = {
    @SuppressWarnings(Array("unchecked")) //  factories maps Class<P> to PrimitiveFactory<P, KeyProtoT>.
    val factory: PrimitiveFactory[P, KeyProtoT] = factories.get(primitiveClass).orNull.asInstanceOf[PrimitiveFactory[P, KeyProtoT]]
    if (factory == null) throw new IllegalArgumentException(s"Requested primitive class ${primitiveClass.getCanonicalName} not supported.")
    factory.getPrimitive(key)
  }

  /**
   * Returns a set containing the supported primitives.
   */
  final def supportedPrimitives: Set[Class[?]] = factories.keySet

  /**
   * Returns the first class object of the first supported primitive, or {@code Class<Void>} if the
   * key manager supports no primitive at all.
   */
  final def firstSupportedPrimitiveClass: Class[?] = firstPrimitiveClass

  /**
   * Returns the {@link KeyFactory} for this key type.
   *
   * <p>By default, this throws an UnsupportedOperationException. Hence, if an implementation does
   * not support creating primitives, no implementation is required.
   *
   * @throws UnsupportedOperationException if the manager does not support creating primitives.
   */
  def keyFactory: KeyFactory[KeyProtoT] = {
    throw new UnsupportedOperationException("Creating keys is not supported.")
  }
}