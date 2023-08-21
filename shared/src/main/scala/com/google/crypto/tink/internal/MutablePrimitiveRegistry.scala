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
import com.google.crypto.tink.PrimitiveSet
import com.google.crypto.tink.PrimitiveWrapper
import java.security.GeneralSecurityException
import java.util.concurrent.atomic.AtomicReference

/**
 * A Mutable version of the {@link PrimitiveRegistry}.
 *
 * <p>This class probably shouldn't exist; it would be better if we had only the
 * PrimitiveRegistry. However, at the moment, we need this, since a call to e.g.
 *
 * <pre> AesCmacKeyManager.register() </pre>
 *
 * should register such an object into a global, mutable registry.
 */
object MutablePrimitiveRegistry {
  private var _globalInstance = new MutablePrimitiveRegistry

  def globalInstance: MutablePrimitiveRegistry = _globalInstance

  def resetGlobalInstanceTestOnly(): Unit = {
    _globalInstance = new MutablePrimitiveRegistry
  }
}

final class MutablePrimitiveRegistry private[internal] {
  final private val registry = new AtomicReference[PrimitiveRegistry](new PrimitiveRegistry.Builder().build)

  /**
   * Registers a key primitive constructor for later use in {@link # getPrimitive}.
   *
   * <p>This registers a primitive constructor which can later be used to create a primitive by
   * calling {@link # getPrimitive}. If a constructor for the pair {@code (KeyT, PrimitiveT)} has
   * already been registered and is the same, then the call is ignored; otherwise, an exception is
   * thrown.
   */
  @throws[GeneralSecurityException]
  def registerPrimitiveConstructor[KeyT <: Key, PrimitiveT](constructor: PrimitiveConstructor[KeyT, PrimitiveT]): Unit = {
    val newRegistry = new PrimitiveRegistry.Builder(registry.get).registerPrimitiveConstructor(constructor).build
    registry.set(newRegistry)
  }

  @throws[GeneralSecurityException]
  def registerPrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT](wrapper: PrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT]): Unit = {
    val newRegistry = new PrimitiveRegistry.Builder(registry.get).registerPrimitiveWrapper(wrapper).build
    registry.set(newRegistry)
  }

  /**
   * Creates a primitive from a given key.
   *
   * <p>This will look up a previously registered constructor for the given pair of {@code (KeyT,
   * PrimitiveT)}, and, if successful, use the registered PrimitiveConstructor object to create the
   * requested primitive. Throws if the required constructor has not been registered, or if the
   * primitive construction threw.
   */
  @throws[GeneralSecurityException]
  def getPrimitive[KeyT <: Key, PrimitiveT](key: KeyT, primitiveClass: Class[PrimitiveT]): PrimitiveT = registry.get.getPrimitive(key, primitiveClass)

  @throws[GeneralSecurityException]
  def getInputPrimitiveClass[WrapperPrimitiveT](wrapperClassObject: Class[WrapperPrimitiveT]): Class[_] = registry.get.getInputPrimitiveClass(wrapperClassObject)

  @throws[GeneralSecurityException]
  def wrap[InputPrimitiveT, WrapperPrimitiveT](primitives: PrimitiveSet[InputPrimitiveT], wrapperClassObject: Class[WrapperPrimitiveT]): WrapperPrimitiveT = registry.get.wrap(primitives, wrapperClassObject)
}