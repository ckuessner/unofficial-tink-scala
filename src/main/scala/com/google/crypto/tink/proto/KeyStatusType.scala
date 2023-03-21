package com.google.crypto.tink.proto

enum KeyStatusType extends Enum[KeyStatusType] {
  case UNKNOWN_STATUS
  case ENABLED
  case DISABLED
  case DESTROYED
  case UNRECOGNIZED
}
