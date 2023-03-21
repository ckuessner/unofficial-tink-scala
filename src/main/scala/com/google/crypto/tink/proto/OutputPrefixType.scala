package com.google.crypto.tink.proto

enum OutputPrefixType extends Enum[OutputPrefixType] {
  case UNKNOWN_PREFIX
  case TINK
  case LEGACY
  case RAW
  case CRUNCHY
  case UNRECOGNIZED
}
