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

import com.google.crypto.tink.Key
import java.security.GeneralSecurityException

/**
 * Create Primitive objects from {@code Key} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 * Note: Before making this public, the class name should be reconsidered. (Currently the desirable
 * option "PrimitiveFactory" is unavailable because such a class already exists.)
 */
//TODO(lizatretyakova): reconsider the name before this class becomes public.
object PrimitiveConstructor {
  /**
   * A function which creates a Primitive object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link # create}. Users
   * should not use this directly; see the explanation in {@link # create}.
   */
  trait PrimitiveConstructionFunction[KeyT <: Key, PrimitiveT] {
    @throws[GeneralSecurityException]
    def constructPrimitive(key: KeyT): PrimitiveT
  }

  /**
   * Creates a PrimitiveConstructor object.
   *
   * <p>This function should only be used by Primitives authors, that is, end users should almost
   * certainly avoid using this function directly, and instead use their respective Primitive's
   * {@code register()} method.
   *
   * <p>That being said, one typically creates a PrimitiveConstructor object by writing a function
   *
   * <pre>{@code
   * class MyClass {
   * private static MyPrimitive getPrimitive(MyKey key)
   * throws GeneralSecurityException {
   * ...
   * }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code PrimitiveConstructor}:
   *
   * <pre>{@code
   * PrimitiveConstructor<MyKey, MyPrimitive> serializer =
   * PrimitiveConstructor.create(MyClass::getPrimitive, MyKey.class,
   * MyPrimitive.class);
   * }</pre>
   *
   * -- and the resulting {@code PrimitiveConstructor} object can in turn be registered in a
   * {@code PrimitiveRegistry}.
   */
  def create[KeyT <: Key, PrimitiveT](function: PrimitiveConstructor.PrimitiveConstructionFunction[KeyT, PrimitiveT],
                                      keyClass: Class[KeyT],
                                      primitiveClass: Class[PrimitiveT]
                                     ): PrimitiveConstructor[KeyT, PrimitiveT] = {
    new PrimitiveConstructor[KeyT, PrimitiveT](keyClass, primitiveClass) {
      @throws[GeneralSecurityException]
      override def constructPrimitive(key: KeyT): PrimitiveT = return function.constructPrimitive(key)
    }
  }
}

abstract class PrimitiveConstructor[KeyT <: Key, PrimitiveT] private(private val keyClass: Class[KeyT], private val primitiveClass: Class[PrimitiveT]) {
  @throws[GeneralSecurityException]
  def constructPrimitive(key: KeyT): PrimitiveT

  def getKeyClass: Class[KeyT] = keyClass

  def getPrimitiveClass: Class[PrimitiveT] = primitiveClass
}