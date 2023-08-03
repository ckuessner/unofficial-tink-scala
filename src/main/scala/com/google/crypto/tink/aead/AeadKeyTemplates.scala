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

import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.proto.OutputPrefixType

/**
 * Pre-generated {@link KeyTemplate} for {@link com.google.crypto.tink.Aead} keys.
 *
 * <p>We recommend to avoid this class to keep dependencies small.
 *
 * <ul>
 * <li>Using this class adds a dependency on protobuf. We hope that eventually it is possible to
 * use Tink without a dependency on protobuf.
 * <li>Using this class adds a dependency on classes for all involved key types.
 * </ul>
 *
 * These dependencies all come from static class member variables, which are initialized when the
 * class is loaded. This implies that static analysis and code minimization tools (such as proguard)
 * cannot remove the usages either.
 *
 * <p>Instead, we recommend to use {@code KeysetHandle.generateEntryFromParametersName} or {@code
 * KeysetHandle.generateEntryFromParameters}.
 *
 * <p>One can use these templates to generate new [[com.google.crypto.tink.proto.Keyset]] with
 * [[com.google.crypto.tink.KeysetHandle.generateNew]]. To generate a new keyset that contains a
 * single [[com.google.crypto.tink.proto.XChaCha20Poly1305Key]], one can do:
 *
 * <pre>{@code
 * Config.register(AeadConfig.TINK_1_1_0);
 * KeysetHandle handle = KeysetHandle.generateNew(AeadKeyTemplates.XCHACHA20_POLY1305);
 * Aead aead = handle.getPrimitive(Aead.class);
 * }</pre>
 *
 * @since 1.0.0
 */
object AeadKeyTemplates {
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
 * com.google.crypto.tink.proto.ChaCha20Poly1305Key}.
   *
   * @since 1.1.0
   */
  val CHACHA20_POLY1305: KeyTemplate = KeyTemplate.newBuilder.setTypeUrl(new ChaCha20Poly1305KeyManager().getKeyType).setOutputPrefixType(OutputPrefixType.TINK).build
  /**
   * A {@link KeyTemplate} that generates new instances of {@link
 * com.google.crypto.tink.proto.XChaCha20Poly1305Key}.
   *
   * @since 1.3.0
   */
  val XCHACHA20_POLY1305: KeyTemplate = KeyTemplate.newBuilder.setTypeUrl(new XChaCha20Poly1305KeyManager().getKeyType).setOutputPrefixType(OutputPrefixType.TINK).build
}