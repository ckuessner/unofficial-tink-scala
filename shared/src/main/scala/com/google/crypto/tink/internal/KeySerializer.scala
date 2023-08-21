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

import com.google.crypto.tink.{Key, SecretKeyAccess}

import java.security.GeneralSecurityException

/**
 * Serializes {@code Key} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
object KeySerializer {
  /**
   * A function which serializes a key.
   *
   * <p>This interface exists only so we have a type we can reference in {@link # create}. Users
   * should not use this directly; see the explanation in {@link # create}.
   */
  @FunctionalInterface trait KeySerializationFunction[KeyT <: Key, SerializationT <: Serialization] {
    @throws[GeneralSecurityException]
    def serializeKey(key: KeyT, access: SecretKeyAccess): SerializationT
  }

  /**
   * Creates a KeySerializer object.
   *
   * <p>In order to create a KeySerializer object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   * private static MySerialization serialize(MyKey key, @Nullable SecretKeyAccess access)
   * throws GeneralSecurityException {
   * ...
   * }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code KeySerializer}:
   *
   * <pre>{@code
   * KeySerializer<MyKey, MySerialization> serializer =
   * KeySerializer.create(MyClass::serialize, MyKey.class, MySerialization.class);
   * }</pre>
   *
   * <p>Note that calling this function twice will result in objects which are not equal according
   * to {@code Object.equals}, and hence cannot be used to re-register a previously registered
   * object.
   */
  def create[KeyT <: Key, SerializationT <: Serialization](function: KeySerializer.KeySerializationFunction[KeyT, SerializationT], keyClass: Class[KeyT], serializationClass: Class[SerializationT]): KeySerializer[KeyT, SerializationT] = {
    new KeySerializer[KeyT, SerializationT](keyClass, serializationClass) {
      @throws[GeneralSecurityException]
      override def serializeKey(key: KeyT, access: SecretKeyAccess): SerializationT = return function.serializeKey(key, access)
    }
  }
}

abstract class KeySerializer[KeyT <: Key, SerializationT <: Serialization] private(private val keyClass: Class[KeyT], private val serializationClass: Class[SerializationT]) {
  @throws[GeneralSecurityException]
  def serializeKey(key: KeyT, access: SecretKeyAccess): SerializationT

  def getKeyClass: Class[KeyT] = keyClass

  def getSerializationClass: Class[SerializationT] = serializationClass
}