package com.google.crypto.tink

import com.google.crypto.tink.subtle.EngineFactory
import org.scalatest.flatspec.AnyFlatSpecLike
import org.scalatest.matchers.should.Matchers.shouldEqual

class SHA512Test extends AnyFlatSpecLike {
  private def md() = EngineFactory.sha512MessageDigestInstance

  "BouncyCastle SHA-512 implementation" should "work for single byte update" in {
    val digest = md()
    digest.update(4.byteValue)
    digest.digest() shouldEqual Array(-75, -72, -57, 37, 80, 123, 91, 19, 21, -114, 2, 13, -106, -2, 76, -5, -10, -41, 116, -32, -111, 97, -30, -75, -103, -72, -13, 90, -29, 31, 22, -29, -107, -126, 94, -34, -8, -86, 105, -83, 48, 78, -8, 15, -19, -101, -86, 5, -128, -46, 71, -51, -124, -27, 122, 42, -30, 57, -82, -55, 13, 45, 88, 105)
  }

  it should "reset after call to digest()" in {
    val digest = md()
    digest.update(4.byteValue)
    digest.digest()
    digest.update(4.byteValue)
    digest.digest() shouldEqual Array(-75, -72, -57, 37, 80, 123, 91, 19, 21, -114, 2, 13, -106, -2, 76, -5, -10, -41, 116, -32, -111, 97, -30, -75, -103, -72, -13, 90, -29, 31, 22, -29, -107, -126, 94, -34, -8, -86, 105, -83, 48, 78, -8, 15, -19, -101, -86, 5, -128, -46, 71, -51, -124, -27, 122, 42, -30, 57, -82, -55, 13, 45, 88, 105)
  }

  it should "work for empty input" in {
    md().digest() shouldEqual Array(-49, -125, -31, 53, 126, -17, -72, -67, -15, 84, 40, 80, -42, 109, -128, 7, -42, 32, -28, 5, 11, 87, 21, -36, -125, -12, -87, 33, -45, 108, -23, -50, 71, -48, -47, 60, 93, -123, -14, -80, -1, -125, 24, -46, -121, 126, -20, 47, 99, -71, 49, -67, 71, 65, 122, -127, -91, 56, 50, 122, -7, 39, -38, 62)
  }

  it should "work for multiple single byte updates" in {
    val digest = md()
    digest.update(4.byteValue)
    digest.digest() shouldEqual Array(-75, -72, -57, 37, 80, 123, 91, 19, 21, -114, 2, 13, -106, -2, 76, -5, -10, -41, 116, -32, -111, 97, -30, -75, -103, -72, -13, 90, -29, 31, 22, -29, -107, -126, 94, -34, -8, -86, 105, -83, 48, 78, -8, 15, -19, -101, -86, 5, -128, -46, 71, -51, -124, -27, 122, 42, -30, 57, -82, -55, 13, 45, 88, 105)

    // Should be reset by digest() call
    digest.update(4.byteValue)
    digest.digest() shouldEqual Array(-75, -72, -57, 37, 80, 123, 91, 19, 21, -114, 2, 13, -106, -2, 76, -5, -10, -41, 116, -32, -111, 97, -30, -75, -103, -72, -13, 90, -29, 31, 22, -29, -107, -126, 94, -34, -8, -86, 105, -83, 48, 78, -8, 15, -19, -101, -86, 5, -128, -46, 71, -51, -124, -27, 122, 42, -30, 57, -82, -55, 13, 45, 88, 105)
  }

  it should "work for update with array spanning multiple buffers" in {
    val digest = md()
    digest.update(Array.fill(3000)(42.toByte))
    digest.digest() shouldEqual Array(66, 98, -89, 22, -121, -107, -5, 44, -45, -99, -92, -15, -49, 69, -79, 77, 99, 58, -49, -23, -113, -70, 72, 20, 44, -62, 90, 56, -2, -66, -81, 34, 24, 5, 48, -13, 55, -5, -109, -23, -115, 5, 3, -128, -40, 67, 124, -128, 81, 3, 8, -28, -24, -23, -34, -79, -102, 2, -124, -102, 46, -32, -49, -11)
  }

  it should "work for update with length and offset being used" in {
    val digest = md()
    digest.update(Array.fill(3000)(42.toByte), 2, 33)
    digest.digest() shouldEqual Array(-42, -85, 74, -91, -90, 125, -118, -26, -47, -98, 82, 115, -108, 100, 122, -9, -119, 20, 22, -21, -126, 91, -72, -3, -28, 56, -66, -59, 121, -98, -46, -1, 84, 112, 86, -109, -1, 44, 106, -127, 111, -23, 73, -10, 71, -61, 45, 8, 43, 65, -48, 114, 44, -104, -97, 50, -8, -7, 7, 93, 96, 66, 11, 126)
  }
}
