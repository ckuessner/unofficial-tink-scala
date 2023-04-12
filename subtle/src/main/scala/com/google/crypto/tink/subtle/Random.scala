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
package com.google.crypto.tink.subtle

import java.security.SecureRandom

/**
 * A simple wrapper of {@link SecureRandom}.
 *
 * @since 1.0.0
 */
object Random {
  private val localRandom = new ThreadLocal[SecureRandom]() {
    override protected def initialValue: SecureRandom = newDefaultSecureRandom
  }

  private def newDefaultSecureRandom = {
    val retval = new SecureRandom
    retval.nextLong // force seeding
    retval
  }

  /** @return a random byte array of size {@code size}. */
  def randBytes(size: Int): Array[Byte] = {
    val rand = new Array[Byte](size)
    localRandom.get.nextBytes(rand)
    rand
  }

  def randInt(max: Int): Int = localRandom.get.nextInt(max)

  def randInt: Int = localRandom.get.nextInt
}