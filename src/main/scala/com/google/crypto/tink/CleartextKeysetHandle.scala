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
package com.google.crypto.tink

import com.google.crypto.tink.proto.Keyset
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * Static methods for reading or writing cleartext keysets.
 *
 * <h3>WARNING</h3>
 *
 * <p>Reading or writing cleartext keysets is a bad practice, usage of this API should be
 * restricted. Users can read encrypted keysets using {@link KeysetHandle# read}.
 *
 * @since 1.0.0
 */
object CleartextKeysetHandle {
  /**
   * @return a new {@link KeysetHandle} from a {@link Keyset} read with {@code reader}.
   * @throws GeneralSecurityException when the keyset is invalid or can't be read.
   */
  @throws[GeneralSecurityException]
  @throws[IOException]
  def read(reader: KeysetReader): KeysetHandle = KeysetHandle.fromKeyset(reader.read)

  /**
   * @return the keyset underlying this {@code keysetHandle}.
   */
  def getKeyset(keysetHandle: KeysetHandle): Keyset = keysetHandle.getKeyset

  /** Returns a KeysetHandle for {@code keyset}. */
  @throws[GeneralSecurityException]
  def fromKeyset(keyset: Keyset): KeysetHandle = KeysetHandle.fromKeyset(keyset)
}

final class CleartextKeysetHandle private {
}