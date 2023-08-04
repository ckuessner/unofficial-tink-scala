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
package com.google.crypto.tink.util

import com.google.crypto.tink.SecretKeyAccess
import com.google.crypto.tink.annotations.Alpha
import com.google.crypto.tink.subtle.Random
import java.security.MessageDigest
//import com.google.errorprone.annotations.Immutable;

/** A class storing an immutable byte array, protecting the data via {@link SecretKeyAccess}. */
@Alpha object SecretBytes {
  /**
   * Creates a new SecretBytes with the contents given in {@code value}.
   *
   * <p>The parameter {@code access} must be non-null.
   */
    def copyFrom(value: Array[Byte], access: SecretKeyAccess): SecretBytes = {
      if (access == null) throw new NullPointerException("SecretKeyAccess required")
      new SecretBytes(Bytes.copyFrom(value))
    }

    /** Creates a new SecretBytes with bytes chosen uniformly at random of length {@code length}. */
      def randomBytes(length: Int) = new SecretBytes(Bytes.copyFrom(Random.randBytes(length)))
}

@Alpha final class SecretBytes private(private val bytes: Bytes) {
  /**
   * Returns a copy of the bytes wrapped by this object.
   *
   * <p>The parameter {@code access} must be non-null.
   */
  def toByteArray(access: SecretKeyAccess): Array[Byte] = {
    if (access == null) throw new NullPointerException("SecretKeyAccess required")
    bytes.toByteArray
  }

  /** Returns the length of the bytes wrapped by this object. */
  def size: Int = bytes.size

  /**
   * Returns true if the {@code other} byte array has the same bytes, in time depending only on the
   * length of both SecretBytes objects.
   */
  def equalsSecretBytes(other: SecretBytes): Boolean = {
    val myArray = bytes.toByteArray
    val otherArray = other.bytes.toByteArray
    MessageDigest.isEqual(myArray, otherArray)
  }
}