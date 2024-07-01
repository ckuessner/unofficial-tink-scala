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
package com.google.crypto.tink.internal

import com.google.crypto.tink.aead.{ChaCha20Poly1305ProtoSerialization, XChaCha20Poly1305ProtoSerialization}
import com.google.crypto.tink.signature.Ed25519ProtoSerialization
import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.{Key, SecretKeyAccess}

import java.security.GeneralSecurityException
import java.util
import java.util.Objects
import java.util.function.Function
import java.util.stream.{Collectors, Stream}

/**
 * Allows acquiring {@code KeySerializer} and {@code KeyParser} objects, and parsing/serializing keys and key formats
 * with such objects.
 */
object SerializationRegistry {
  private val keySerializerMap: Map[SerializationRegistry.SerializerIndex, KeySerializer[?, ?]] = Seq(
    ChaCha20Poly1305ProtoSerialization.KEY_SERIALIZER,
    XChaCha20Poly1305ProtoSerialization.KEY_SERIALIZER,
    Ed25519ProtoSerialization.PRIVATE_KEY_SERIALIZER,
    Ed25519ProtoSerialization.PUBLIC_KEY_SERIALIZER
  ).map(serializer => new SerializationRegistry.SerializerIndex(serializer.getKeyClass, serializer.getSerializationClass) -> serializer)
    .toMap

  private val keyParserMap: Map[SerializationRegistry.ParserIndex, KeyParser[?]] = Seq(
    ChaCha20Poly1305ProtoSerialization.KEY_PARSER,
    XChaCha20Poly1305ProtoSerialization.KEY_PARSER,
    Ed25519ProtoSerialization.PRIVATE_KEY_PARSER,
    Ed25519ProtoSerialization.PUBLIC_KEY_PARSER
  ).map(parser => new SerializationRegistry.ParserIndex(parser.getSerializationClass, parser.getObjectIdentifier) -> parser)
    .toMap

  private[SerializationRegistry] class SerializerIndex private[SerializationRegistry](private val keyClass: Class[?], private val keySerializationClass: Class[? <: Serialization]) {
    override def equals(o: Any): Boolean = {
      if (!o.isInstanceOf[SerializationRegistry.SerializerIndex]) return false
      val other = o.asInstanceOf[SerializationRegistry.SerializerIndex]
      other.keyClass == keyClass && other.keySerializationClass == keySerializationClass
    }

    override def hashCode: Int = Objects.hash(keyClass, keySerializationClass)

    override def toString: String = keyClass.getSimpleName + " with serialization type: " + keySerializationClass.getSimpleName
  }

  private[SerializationRegistry] class ParserIndex private[SerializationRegistry](private val keySerializationClass: Class[? <: Serialization], private val serializationIdentifier: Bytes) {
    override def equals(o: Any): Boolean = {
      if (!o.isInstanceOf[SerializationRegistry.ParserIndex]) return false
      val other = o.asInstanceOf[SerializationRegistry.ParserIndex]
      other.keySerializationClass == keySerializationClass && other.serializationIdentifier == serializationIdentifier
    }

    override def hashCode: Int = Objects.hash(keySerializationClass, serializationIdentifier)

    override def toString: String = keySerializationClass.getSimpleName + ", object identifier: " + serializationIdentifier
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  def hasParserForKey[SerializationT <: Serialization](serializedKey: SerializationT): Boolean = {
    val index = new SerializationRegistry.ParserIndex(serializedKey.getClass, serializedKey.getObjectIdentifier)
    keyParserMap.contains(index)
  }

  /**
   * Parses the given serialization into a Key.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  @throws[GeneralSecurityException]
  def parseKey[SerializationT <: Serialization](serializedKey: SerializationT, access: SecretKeyAccess): Key = {
    val index = new SerializationRegistry.ParserIndex(serializedKey.getClass, serializedKey.getObjectIdentifier)
    if (!keyParserMap.contains(index)) throw new GeneralSecurityException("No Key Parser for requested key type " + index + " available")
    @SuppressWarnings(Array("unchecked")) // We know we only insert like this.
    val parser: KeyParser[SerializationT] = keyParserMap(index).asInstanceOf[KeyParser[SerializationT]]
    parser.parseKey(serializedKey, access)
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  def hasSerializerForKey[KeyT <: Key, SerializationT <: Serialization](key: KeyT, serializationClass: Class[SerializationT]): Boolean = {
    val index = new SerializationRegistry.SerializerIndex(key.getClass, serializationClass)
    keySerializerMap.contains(index)
  }

  /**
   * Serializes a given Key into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  @throws[GeneralSecurityException]
  def serializeKey[KeyT <: Key, SerializationT <: Serialization](key: KeyT, serializationClass: Class[SerializationT], access: SecretKeyAccess): SerializationT = {
    val index = new SerializationRegistry.SerializerIndex(key.getClass, serializationClass)
    if (!keySerializerMap.contains(index)) throw new GeneralSecurityException("No Key serializer for " + index + " available")
    @SuppressWarnings(Array("unchecked")) // We know we only insert like this.
    val serializer: KeySerializer[KeyT, SerializationT] = keySerializerMap(index).asInstanceOf[KeySerializer[KeyT, SerializationT]]
    serializer.serializeKey(key, access)
  }
}