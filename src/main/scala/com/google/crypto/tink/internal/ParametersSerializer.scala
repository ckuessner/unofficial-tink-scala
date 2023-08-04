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

import com.google.crypto.tink.Parameters
import java.security.GeneralSecurityException

/**
 * Serializes {@code Parameters} objects into {@code Serialization} objects of a certain kind.
 *
 * <p>This class should eventually be in Tinks public API -- however, it might still change before
 * that.
 */
object ParametersSerializer {
  /**
   * A function which serializes a Parameters object.
   *
   * <p>This interface exists only so we have a type we can reference in {@link # create}. Users
   * should not use this directly; see the explanation in {@link # create}.
   */
  trait ParametersSerializationFunction[ParametersT <: Parameters, SerializationT <: Serialization] {
    @throws[GeneralSecurityException]
    def serializeParameters(key: ParametersT): SerializationT
  }

  /**
   * Creates a ParametersSerializer object.
   *
   * <p>In order to create a ParametersSerializer object, one typically writes a function
   *
   * <pre>{@code
   * class MyClass {
   * private static MySerialization serializeParameters(MyParameters Parameters)
   * throws GeneralSecurityException {
   * ...
   * }
   * }
   * }</pre>
   *
   * This function can then be used to create a {@code ParametersSerializer}:
   *
   * <pre>{@code
   * ParametersSerializer<MyParameters, MySerialization> serializer =
   * ParametersSerializer.create(MyClass::serializeParameters, MyParameters.class,
   * MySerialization.class);
   * }</pre>
   */
  def create[ParametersT <: Parameters, SerializationT <: Serialization](function: ParametersSerializer.ParametersSerializationFunction[ParametersT, SerializationT],
                                                                         parametersClass: Class[ParametersT],
                                                                         serializationClass: Class[SerializationT]
                                                                        ): ParametersSerializer[ParametersT, SerializationT] =
    new ParametersSerializer[ParametersT, SerializationT](parametersClass, serializationClass) {
      @throws[GeneralSecurityException]
      override def serializeParameters(parameters: ParametersT): SerializationT = return function.serializeParameters(parameters)
    }
}

abstract class ParametersSerializer[ParametersT <: Parameters, SerializationT <: Serialization] private(private val parametersClass: Class[ParametersT], private val serializationClass: Class[SerializationT]) {
  @throws[GeneralSecurityException]
  def serializeParameters(parameters: ParametersT): SerializationT

  def getParametersClass: Class[ParametersT] = parametersClass

  def getSerializationClass: Class[SerializationT] = serializationClass
}