// Copyright 2023 Google LLC
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
package com.google.crypto.tink.aead

import com.google.common.truth.Truth.assertThat
import org.junit.Assert.{assertFalse, assertTrue}
import org.junit.{Assert, Test}
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(classOf[JUnit4]) object XChaCha20Poly1305ParametersTest {
  private val NO_PREFIX = XChaCha20Poly1305Parameters.Variant.NO_PREFIX
  private val TINK = XChaCha20Poly1305Parameters.Variant.TINK
  private val CRUNCHY = XChaCha20Poly1305Parameters.Variant.CRUNCHY
}

@RunWith(classOf[JUnit4]) final class XChaCha20Poly1305ParametersTest {
  @Test
  @throws[Exception]
  def buildParametersAndGetProperties(): Unit = {
    val parameters = XChaCha20Poly1305Parameters.create
    assertThat(parameters.getVariant).isEqualTo(XChaCha20Poly1305ParametersTest.NO_PREFIX)
    assertFalse(parameters.hasIdRequirement)
  }

  @Test
  @throws[Exception]
  def buildParameters_setVariantExplicitly(): Unit = {
    val parameters = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX)
    assertThat(parameters.getVariant).isEqualTo(XChaCha20Poly1305ParametersTest.NO_PREFIX)
    assertFalse(parameters.hasIdRequirement)
  }

  @Test
  @throws[Exception]
  def buildParameters_tink(): Unit = {
    val parameters = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)
    assertThat(parameters.getVariant).isEqualTo(XChaCha20Poly1305ParametersTest.TINK)
    assertTrue(parameters.hasIdRequirement)
  }

  @Test
  @throws[Exception]
  def buildParameters_crunchy(): Unit = {
    val parameters = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY)
    assertThat(parameters.getVariant).isEqualTo(XChaCha20Poly1305ParametersTest.CRUNCHY)
    assertTrue(parameters.hasIdRequirement)
  }

  @Test
  @throws[Exception]
  def testEqualsAndEqualHashCode_noPrefix(): Unit = {
    val parametersNoPrefix0 = XChaCha20Poly1305Parameters.create
    val parametersNoPrefix1 = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX)
    assertThat(parametersNoPrefix0).isEqualTo(parametersNoPrefix1)
    assertThat(parametersNoPrefix0.hashCode).isEqualTo(parametersNoPrefix1.hashCode)
  }

  @Test
  @throws[Exception]
  def testEqualsAndEqualHashCode_tink(): Unit = {
    val parametersTink0 = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)
    val parametersTink1 = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)
    assertThat(parametersTink0).isEqualTo(parametersTink1)
    assertThat(parametersTink0.hashCode).isEqualTo(parametersTink1.hashCode)
  }

  @Test
  @throws[Exception]
  def testEqualsAndEqualHashCode_crunchy(): Unit = {
    val parametersCrunchy0 = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY)
    val parametersCrunchy1 = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY)
    assertThat(parametersCrunchy0).isEqualTo(parametersCrunchy1)
    assertThat(parametersCrunchy0.hashCode).isEqualTo(parametersCrunchy1.hashCode)
  }

  @Test
  @throws[Exception]
  def testEqualsAndEqualHashCode_different(): Unit = {
    val parametersNoPrefix = XChaCha20Poly1305Parameters.create
    val parametersTink = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK)
    val parametersCrunchy = XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY)
    assertThat(parametersNoPrefix).isNotEqualTo(parametersTink)
    assertThat(parametersNoPrefix.hashCode).isNotEqualTo(parametersTink.hashCode)
    assertThat(parametersNoPrefix).isNotEqualTo(parametersCrunchy)
    assertThat(parametersNoPrefix.hashCode).isNotEqualTo(parametersCrunchy.hashCode)
    assertThat(parametersTink).isNotEqualTo(parametersNoPrefix)
    assertThat(parametersTink.hashCode).isNotEqualTo(parametersNoPrefix.hashCode)
    assertThat(parametersTink).isNotEqualTo(parametersCrunchy)
    assertThat(parametersTink.hashCode).isNotEqualTo(parametersCrunchy.hashCode)
    assertThat(parametersCrunchy).isNotEqualTo(parametersNoPrefix)
    assertThat(parametersCrunchy.hashCode).isNotEqualTo(parametersNoPrefix.hashCode)
    assertThat(parametersCrunchy).isNotEqualTo(parametersTink)
    assertThat(parametersCrunchy.hashCode).isNotEqualTo(parametersTink.hashCode)
  }
}