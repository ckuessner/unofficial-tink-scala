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
import java.util
import java.util.Objects

/**
 * Allows registering {@code PrimitiveConstructor} objects, and creating primitives with those
 * objects.
 */
object PrimitiveRegistry {
  /** Allows building PrimitiveRegistry objects. */
  final class Builder {
    private[PrimitiveRegistry] var primitiveConstructorMap: util.Map[PrimitiveRegistry.PrimitiveConstructorIndex, PrimitiveConstructor[_, _]] = new util.HashMap[PrimitiveRegistry.PrimitiveConstructorIndex, PrimitiveConstructor[_, _]]
    private[PrimitiveRegistry] var primitiveWrapperMap: util.Map[Class[_], PrimitiveWrapper[_, _]] = new util.HashMap[Class[_], PrimitiveWrapper[_, _]]

    def this(registry: PrimitiveRegistry) = {
      this()
      primitiveConstructorMap = new util.HashMap[PrimitiveRegistry.PrimitiveConstructorIndex, PrimitiveConstructor[_, _]](registry.primitiveConstructorMap)
      primitiveWrapperMap = new util.HashMap[Class[_], PrimitiveWrapper[_, _]](registry.primitiveWrapperMap)
    }

    /**
     * Registers a primitive constructor for later use in {@link # getPrimitive}.
     *
     * <p>This registers a primitive constructor which can later be used to create a primitive
     * by calling {@link # getPrimitive}. If a constructor for the pair {@code (KeyT, PrimitiveT)}
     * has already been registered, this checks if they are the same. If they are, the call is
     * ignored, otherwise an exception is thrown.
     */
    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def registerPrimitiveConstructor[KeyT <: Key, PrimitiveT](primitiveConstructor: PrimitiveConstructor[KeyT, PrimitiveT]): PrimitiveRegistry.Builder = {
      if (primitiveConstructor == null) throw new NullPointerException("primitive constructor must be non-null")
      val index = new PrimitiveRegistry.PrimitiveConstructorIndex(primitiveConstructor.getKeyClass, primitiveConstructor.getPrimitiveClass)
      if (primitiveConstructorMap.containsKey(index)) {
        val existingConstructor = primitiveConstructorMap.get(index)
        if (!(existingConstructor == primitiveConstructor) || !(primitiveConstructor == existingConstructor)) throw new GeneralSecurityException("Attempt to register non-equal PrimitiveConstructor object for already existing" + " object of type: " + index)
      }
      else primitiveConstructorMap.put(index, primitiveConstructor)
      this
    }

    //@CanIgnoreReturnValue
    @throws[GeneralSecurityException]
    def registerPrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT](wrapper: PrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT]): PrimitiveRegistry.Builder = {
      if (wrapper == null) throw new NullPointerException("wrapper must be non-null")
      val wrapperClassObject = wrapper.getPrimitiveClass
      if (primitiveWrapperMap.containsKey(wrapperClassObject)) {
        val existingPrimitiveWrapper = primitiveWrapperMap.get(wrapperClassObject)
        if (!(existingPrimitiveWrapper == wrapper) || !(wrapper == existingPrimitiveWrapper)) throw new GeneralSecurityException("Attempt to register non-equal PrimitiveWrapper object or input class object for" + " already existing object of type" + wrapperClassObject)
      }
      else primitiveWrapperMap.put(wrapperClassObject, wrapper)
      this
    }

    private[internal] def build = new PrimitiveRegistry(this)
  }

  final private[PrimitiveRegistry] class PrimitiveConstructorIndex private[PrimitiveRegistry](private val keyClass: Class[_], private val primitiveClass: Class[_]) {
    override def equals(o: Any): Boolean = {
      if (!o.isInstanceOf[PrimitiveRegistry.PrimitiveConstructorIndex]) return false
      val other = o.asInstanceOf[PrimitiveRegistry.PrimitiveConstructorIndex]
      other.keyClass == keyClass && other.primitiveClass == primitiveClass
    }

    override def hashCode: Int = Objects.hash(keyClass, primitiveClass)

    override def toString: String = keyClass.getSimpleName + " with primitive type: " + primitiveClass.getSimpleName
  }
}

class PrimitiveRegistry private(builder: PrimitiveRegistry.Builder) {
  final private val primitiveConstructorMap: util.Map[PrimitiveRegistry.PrimitiveConstructorIndex, PrimitiveConstructor[_, _]] = new util.HashMap[PrimitiveRegistry.PrimitiveConstructorIndex, PrimitiveConstructor[_, _]](builder.primitiveConstructorMap)
  final private val primitiveWrapperMap: util.Map[Class[_], PrimitiveWrapper[_, _]] = new util.HashMap[Class[_], PrimitiveWrapper[_, _]](builder.primitiveWrapperMap)


  /**
   * Creates a primitive from a given key.
   *
   * <p>This will look up a previously registered constructor for the given pair of {@code (KeyT,
   * PrimitiveT)}, and, if successful, use the registered PrimitiveConstructor object to create the
   * requested primitive. Throws on a failed lookup, or if the primitive construction threw.
   */
  @throws[GeneralSecurityException]
  def getPrimitive[KeyT <: Key, PrimitiveT](key: KeyT, primitiveClass: Class[PrimitiveT]): PrimitiveT = {
    val index = new PrimitiveRegistry.PrimitiveConstructorIndex(key.getClass, primitiveClass)
    if (!primitiveConstructorMap.containsKey(index)) throw new GeneralSecurityException("No PrimitiveConstructor for " + index + " available")
    @SuppressWarnings(Array("unchecked")) // We know we only insert like this.
    val primitiveConstructor: PrimitiveConstructor[KeyT, PrimitiveT] = primitiveConstructorMap.get(index).asInstanceOf[PrimitiveConstructor[KeyT, PrimitiveT]]
    primitiveConstructor.constructPrimitive(key)
  }

  @throws[GeneralSecurityException]
  def getInputPrimitiveClass(wrapperClassObject: Class[_]): Class[_] = {
    if (!primitiveWrapperMap.containsKey(wrapperClassObject)) throw new GeneralSecurityException("No input primitive class for " + wrapperClassObject + " available")
    primitiveWrapperMap.get(wrapperClassObject).getInputPrimitiveClass
  }

  @throws[GeneralSecurityException]
  def wrap[InputPrimitiveT, WrapperPrimitiveT](primitives: PrimitiveSet[InputPrimitiveT], wrapperClassObject: Class[WrapperPrimitiveT]): WrapperPrimitiveT = {
    if (!primitiveWrapperMap.containsKey(wrapperClassObject)) throw new GeneralSecurityException("No wrapper found for " + wrapperClassObject)
    @SuppressWarnings(Array("unchecked")) // We know this is how this map is organized.
    val wrapper: PrimitiveWrapper[_, WrapperPrimitiveT] = primitiveWrapperMap.get(wrapperClassObject).asInstanceOf[PrimitiveWrapper[_, WrapperPrimitiveT]]
    if (!(primitives.getPrimitiveClass == wrapper.getInputPrimitiveClass) || !(wrapper.getInputPrimitiveClass == primitives.getPrimitiveClass)) throw new GeneralSecurityException("Input primitive type of the wrapper doesn't match the type of primitives in the provided" + " PrimitiveSet")
    @SuppressWarnings(Array("unchecked")) // The check above ensured this.
    val typedWrapper: PrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT] = wrapper.asInstanceOf[PrimitiveWrapper[InputPrimitiveT, WrapperPrimitiveT]]
    typedWrapper.wrap(primitives)
  }
}