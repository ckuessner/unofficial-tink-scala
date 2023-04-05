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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.Key;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.ChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.aead.XChaCha20Poly1305ProtoSerialization;
import com.google.crypto.tink.util.Bytes;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Allows acquiring {@code KeySerializer} and {@code KeyParser} objects, and parsing/serializing keys and key formats
 * with such objects.
 */
public final class SerializationRegistry {

  private SerializationRegistry() {}
  private final static Map<SerializerIndex, KeySerializer<?, ?>> keySerializerMap;
  private final static Map<ParserIndex, KeyParser<?>> keyParserMap;

  static {
    keySerializerMap = Stream.of(
            ChaCha20Poly1305ProtoSerialization.KEY_SERIALIZER,
            XChaCha20Poly1305ProtoSerialization.KEY_SERIALIZER
    ).collect(Collectors.toMap(
            serializer -> new SerializerIndex(serializer.getKeyClass(), serializer.getSerializationClass()),
            Function.identity())
    );

    keyParserMap = Stream.of(
            ChaCha20Poly1305ProtoSerialization.KEY_PARSER,
            XChaCha20Poly1305ProtoSerialization.KEY_PARSER
    ).collect(Collectors.toMap(
            parser -> new ParserIndex(parser.getSerializationClass(), parser.getObjectIdentifier()),
            Function.identity())
    );
  }

  private static class SerializerIndex {
    private final Class<?> keyClass;
    private final Class<? extends Serialization> keySerializationClass;

    private SerializerIndex(
        Class<?> keyClass, Class<? extends Serialization> keySerializationClass) {
      this.keyClass = keyClass;
      this.keySerializationClass = keySerializationClass;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof SerializerIndex)) {
        return false;
      }
      SerializerIndex other = (SerializerIndex) o;
      return other.keyClass.equals(keyClass)
          && other.keySerializationClass.equals(keySerializationClass);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keyClass, keySerializationClass);
    }

    @Override
    public String toString() {
      return keyClass.getSimpleName()
          + " with serialization type: "
          + keySerializationClass.getSimpleName();
    }
  }

  private static class ParserIndex {
    private final Class<? extends Serialization> keySerializationClass;
    private final Bytes serializationIdentifier;

    private ParserIndex(
        Class<? extends Serialization> keySerializationClass, Bytes serializationIdentifier) {
      this.keySerializationClass = keySerializationClass;
      this.serializationIdentifier = serializationIdentifier;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof ParserIndex)) {
        return false;
      }
      ParserIndex other = (ParserIndex) o;
      return other.keySerializationClass.equals(keySerializationClass)
          && other.serializationIdentifier.equals(serializationIdentifier);
    }

    @Override
    public int hashCode() {
      return Objects.hash(keySerializationClass, serializationIdentifier);
    }

    @Override
    public String toString() {
      return keySerializationClass.getSimpleName()
          + ", object identifier: "
          + serializationIdentifier;
    }
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public static <SerializationT extends Serialization> boolean hasParserForKey(
      SerializationT serializedKey) {
    ParserIndex index =
        new ParserIndex(serializedKey.getClass(), serializedKey.getObjectIdentifier());
    return keyParserMap.containsKey(index);
  }

  /**
   * Parses the given serialization into a Key.
   *
   * <p>This will look up a previously registered parser for the passed in {@code SerializationT}
   * class, and the used object identifier (as indicated by {@code
   * serializedKey.getObjectIdentifier()}), and then parse the object with this parsers.
   */
  public static <SerializationT extends Serialization> Key parseKey(
      SerializationT serializedKey, /*@Nullable*/ SecretKeyAccess access)
      throws GeneralSecurityException {
    ParserIndex index =
        new ParserIndex(serializedKey.getClass(), serializedKey.getObjectIdentifier());

    if (!keyParserMap.containsKey(index)) {
      throw new GeneralSecurityException(
          "No Key Parser for requested key type " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeyParser<SerializationT> parser = (KeyParser<SerializationT>) keyParserMap.get(index);
    return parser.parseKey(serializedKey, access);
  }

  /** Returns true if a parser for this {@code serializedKey} has been registered. */
  public static <KeyT extends Key, SerializationT extends Serialization> boolean hasSerializerForKey(
      KeyT key, Class<SerializationT> serializationClass) {
    SerializerIndex index = new SerializerIndex(key.getClass(), serializationClass);
    return keySerializerMap.containsKey(index);
  }

  /**
   * Serializes a given Key into a "SerializationT" object.
   *
   * <p>This will look up a previously registered serializer for the requested {@code
   * SerializationT} class and the passed in key type, and then call serializeKey on the result.
   */
  public static <KeyT extends Key, SerializationT extends Serialization> SerializationT serializeKey(
      KeyT key, Class<SerializationT> serializationClass, /*@Nullable*/ SecretKeyAccess access)
      throws GeneralSecurityException {
    SerializerIndex index = new SerializerIndex(key.getClass(), serializationClass);
    if (!keySerializerMap.containsKey(index)) {
      throw new GeneralSecurityException("No Key serializer for " + index + " available");
    }
    @SuppressWarnings("unchecked") // We know we only insert like this.
    KeySerializer<KeyT, SerializationT> serializer =
        (KeySerializer<KeyT, SerializationT>) keySerializerMap.get(index);
    return serializer.serializeKey(key, access);
  }
}
