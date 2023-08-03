// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.proto.{HashType, KeyTemplate, OutputPrefixType}
import org.junit.Assert.{assertEquals, assertTrue}
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

/** Tests for AeadKeyTemplates. */
@RunWith(classOf[JUnit4]) class AeadKeyTemplatesTest {
  @Test
  @throws[Exception]
  def chacha20Poly1305(): Unit = {
    val template = AeadKeyTemplates.CHACHA20_POLY1305
    assertEquals(new ChaCha20Poly1305KeyManager().getKeyType, template.getTypeUrl)
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType)
  }

  @Test
  @throws[Exception]
  def xchacha20Poly1305(): Unit = {
    val template = AeadKeyTemplates.XCHACHA20_POLY1305
    assertEquals(new XChaCha20Poly1305KeyManager().getKeyType, template.getTypeUrl)
    assertEquals(OutputPrefixType.TINK, template.getOutputPrefixType)
  }
}