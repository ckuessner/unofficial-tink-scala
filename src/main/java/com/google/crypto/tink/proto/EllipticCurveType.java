// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/common.proto

package com.google.crypto.tink.proto;

/**
 * Protobuf enum {@code google.crypto.tink.EllipticCurveType}
 */
public enum EllipticCurveType
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>UNKNOWN_CURVE = 0;</code>
   */
  UNKNOWN_CURVE(0),
  /**
   * <code>NIST_P256 = 2;</code>
   */
  NIST_P256(2),
  /**
   * <code>NIST_P384 = 3;</code>
   */
  NIST_P384(3),
  /**
   * <code>NIST_P521 = 4;</code>
   */
  NIST_P521(4),
  /**
   * <code>CURVE25519 = 5;</code>
   */
  CURVE25519(5),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>UNKNOWN_CURVE = 0;</code>
   */
  public static final int UNKNOWN_CURVE_VALUE = 0;
  /**
   * <code>NIST_P256 = 2;</code>
   */
  public static final int NIST_P256_VALUE = 2;
  /**
   * <code>NIST_P384 = 3;</code>
   */
  public static final int NIST_P384_VALUE = 3;
  /**
   * <code>NIST_P521 = 4;</code>
   */
  public static final int NIST_P521_VALUE = 4;
  /**
   * <code>CURVE25519 = 5;</code>
   */
  public static final int CURVE25519_VALUE = 5;


  public final int getNumber() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalArgumentException(
          "Can't get the number of an unknown enum value.");
    }
    return value;
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   * @deprecated Use {@link #forNumber(int)} instead.
   */
  @java.lang.Deprecated
  public static EllipticCurveType valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static EllipticCurveType forNumber(int value) {
    switch (value) {
      case 0: return UNKNOWN_CURVE;
      case 2: return NIST_P256;
      case 3: return NIST_P384;
      case 4: return NIST_P521;
      case 5: return CURVE25519;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<EllipticCurveType>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      EllipticCurveType> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<EllipticCurveType>() {
          public EllipticCurveType findValueByNumber(int number) {
            return EllipticCurveType.forNumber(number);
          }
        };

  public final com.google.protobuf.Descriptors.EnumValueDescriptor
      getValueDescriptor() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalStateException(
          "Can't get the descriptor of an unrecognized enum value.");
    }
    return getDescriptor().getValues().get(ordinal());
  }
  public final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptorForType() {
    return getDescriptor();
  }
  public static final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptor() {
    return com.google.crypto.tink.proto.Common.getDescriptor().getEnumTypes().get(0);
  }

  private static final EllipticCurveType[] VALUES = values();

  public static EllipticCurveType valueOf(
      com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
    if (desc.getType() != getDescriptor()) {
      throw new java.lang.IllegalArgumentException(
        "EnumValueDescriptor is not for this type.");
    }
    if (desc.getIndex() == -1) {
      return UNRECOGNIZED;
    }
    return VALUES[desc.getIndex()];
  }

  private final int value;

  private EllipticCurveType(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:google.crypto.tink.EllipticCurveType)
}

