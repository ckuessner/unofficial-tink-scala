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

import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.{Key, SecretKeyAccess}

import java.security.GeneralSecurityException

/**
 * Parses {@code Serialization} objects into {@code Key} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
object KeyParser {
  /**
   * A function which parses a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link # create}. Users
   * should not use this directly; see the explanation in {@link # create}.
   */
  @FunctionalInterface trait KeyParsingFunction[SerializationT <: Serialization] {
    @throws[GeneralSecurityException]
    def parseKey(serialization: SerializationT, access: SecretKeyAccess): Key
  }

  /**
   * Creates a KeyParser object.
   *
   * <p>In order to create a KeyParser object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   * private static MyKey parse(MySerialization key, @Nullable SecretKeyAccess access)
   * throws GeneralSecurityException {
   * ...
   * }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeyParser}:
   *
   * <pre>{@code
   * KeyParser<MyKey, MySerialization> parser =
   * KeyParser.create(MyClass::parse, objectIdentifier, MySerialization.class);
   * }</pre>
   *
   * Note that calling this function twice will result in objects which are not equal according to
   * {@code Object.equals}, and hence cannot be used to re-register a previously registered object.
   *
   * @param function           The function used to parse a Key
   * @param objectIdentifier   The identifier to be returned by {@link # getObjectIdentifier}
   * @param serializationClass The class object corresponding to {@code SerializationT}
   */
  def create[SerializationT <: Serialization](function: KeyParser.KeyParsingFunction[SerializationT], objectIdentifier: Bytes, serializationClass: Class[SerializationT]): KeyParser[SerializationT] = {
    new KeyParser[SerializationT](objectIdentifier, serializationClass) {
      @throws[GeneralSecurityException]
      override def parseKey(serialization: SerializationT, access: SecretKeyAccess): Key = return function.parseKey(serialization, access)
    }
  }
}

abstract class KeyParser[SerializationT <: Serialization] private(private val objectIdentifier: Bytes, private val serializationClass: Class[SerializationT]) {
  /**
   * Parses a serialization into a key.
   *
   * <p>This function is usually called with a Serialization matching the result of {@link
 * getObjectIdentifier}. However, implementations should check that this is the case.
   */
  @throws[GeneralSecurityException]
  def parseKey(serialization: SerializationT, access: SecretKeyAccess): Key

  /**
   * Returns the {@code objectIdentifier} for this serialization.
   *
   * <p>The object identifier is a unique identifier per registry for this object (in the standard
   * proto serialization, it is the typeUrl). In other words, when registering a {@code KeyParser},
   * the registry will invoke this to get the handled object identifier. In order to parse an object
   * of type {@code SerializationT}, the registry will then obtain the {@code objectIdentifier} of
   * this serialization object, and call the parser corresponding to this object.
   */
  final def getObjectIdentifier: Bytes = objectIdentifier

  final def getSerializationClass: Class[SerializationT] = serializationClass
}