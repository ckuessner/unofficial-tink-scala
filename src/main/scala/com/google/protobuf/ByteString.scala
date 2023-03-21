package com.google.protobuf

import java.nio.charset.StandardCharsets

/**
 * Immutable sequence of bytes.
 *
 * Replaces protobufs ByteString implementation.
 *
 * @param bytes The bytes of the ByteString.
 */
class ByteString(private val bytes: Array[Byte]) {
  def toByteArray: Array[Byte] = bytes.clone()

  def byteAt(idx: Int): Byte = bytes(idx)

  def size: Int = bytes.length
}

object ByteString {
  def copyFrom(bytes: Array[Byte]): ByteString = {
    new ByteString(bytes.clone())
  }

  val EMPTY = new ByteString(Array.empty[Byte])

  def copyFromUtf8(text: String): ByteString = {
    new ByteString(text.getBytes(StandardCharsets.UTF_8))
  }
}
