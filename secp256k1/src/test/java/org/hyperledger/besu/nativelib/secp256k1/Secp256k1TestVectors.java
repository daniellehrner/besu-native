/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.nativelib.secp256k1;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;

/**
 * Signatures computed with BouncyCastle's RFC 6979 signer and s normalized to the lower half of the
 * curve order, so they don't depend on libsecp256k1. The first is the vector of Besu's
 * SECP256K1Test.
 */
final class Secp256k1TestVectors {

  static final BigInteger N =
      new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
  static final BigInteger P =
      new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

  record Vector(
      String name,
      byte[] privateKey,
      byte[] messageHash,
      byte[] signature,
      byte[] publicKey,
      byte[] compressedPublicKey) {

    /** r || s, without the recovery id. */
    byte[] compactSignature() {
      return Arrays.copyOf(signature, 64);
    }

    int recoveryId() {
      return signature[64];
    }

    /** x || y, without the 0x04 prefix. */
    byte[] rawPublicKey() {
      return Arrays.copyOfRange(publicKey, 1, 65);
    }

    @Override
    public String toString() {
      return name;
    }
  }

  static final List<Vector> VECTORS =
      List.of(
          vector(
              "besu",
              "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
              "9340487ba7c7964392ba590f171445e41e611186e6e610b613bb9bac18ee491e",
              "d2ce488f4da29e68f22cb05cac1b19b75df170a12b4ad1bdd4531b8e9115c6fb"
                  + "75c1fe50a95e8ccffcbb5482a1e42fbbdd6324131dfe75c3b3b7f9a7c721eccb01",
              "040947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad"
                  + "75aa17564ae80a20bb044ee7a6d903e8e8df624b089c95d66a0570f051e5a05b",
              "030947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad"),
          vector(
              "private key 1",
              "0000000000000000000000000000000000000000000000000000000000000001",
              "9fb31dcb0c55abd4a0ed142e81f9f95f5cadf272866f5090115c80e1f67886b2",
              "0b8e4738ee74fd2278a5a3880a688d6b267137655a901c51d4632e81d0b844bb"
                  + "06833984ad976530ae91fa634465e38c5773e2300815a233bdcfd7d659fa0b0000",
              "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                  + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
              "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
          vector(
              "private key n - 1",
              "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
              "9fb31dcb0c55abd4a0ed142e81f9f95f5cadf272866f5090115c80e1f67886b2",
              "589b4d5c2b8e7961669bf5a963c5a419e7902655fe6a485062e319159d3ec0b1"
                  + "785d65f494378100f594d27d30889f0b1b1bd8e97daa7dd7b7508b8d37b1e53f00",
              "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                  + "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777",
              "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
          vector(
              "zero hash",
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              "0000000000000000000000000000000000000000000000000000000000000000",
              "b2776f88de9f201fa3b0b5161eb090a63a16f9db877fb29ad96efb66f1b59257"
                  + "79115fdcdb93890ad1920c4b789ac732c97ba5272b98206d6b8faa5db7982a5601",
              "044646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
                  + "fe77b4dd0a4bfb95851f3b7355c781dd60f8418fc8a65d14907aff47c903a559",
              "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"),
          vector(
              "hash above the curve order",
              "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
              "acd52da9a73d8a25725bd6ba738209d85f75e3b6ad7d04a1ba9dcc575e4ae830"
                  + "32b4450d8c7bc85a1039b85683802ac0b5c312f4492e2fce2f4c0f94b454433600",
              "0488e2ddeb04657dbd0edadf9c1f98da3b3895faa1f00527934dd35d17542ffe9b"
                  + "1e7640d7737e24e36d208effb77e86affe670a9a497aa7fb52bf4e687a17fff4",
              "0288e2ddeb04657dbd0edadf9c1f98da3b3895faa1f00527934dd35d17542ffe9b"),
          vector(
              "keccak key 0",
              "b6c3c71e68c9c05bd409cd1810145107fcd5493a3f14871d4f6841f5bbee4f6f",
              "edc565322090a82025a600cc8802563e54482cd74363720eff8542a5f626b503",
              "ab1f3d636ac250dc8cf474ce0fe723b5458c81b2ff0d58d9475175158da32122"
                  + "6feaa3dcb3eee6f802f586fc6e86dfe76a6fc7a13c09a96e9f5b6fced3cc32e200",
              "048e5bc2b24126f781f03d1a3a373bca66a428f571663c3787494497d8426f6330"
                  + "b1f810c080dd1009f6cf50b864a25e3744ecfef0eb282deee527bd81d389f24d",
              "038e5bc2b24126f781f03d1a3a373bca66a428f571663c3787494497d8426f6330"),
          vector(
              "keccak key 1",
              "0e42f327ee3cfa7ccfc084a0bb68d05eb627610303012a67afbf1ecd9b0d32fa",
              "b39eb5df54fa9df000267e930421a80ef13538efd85940da7489ccecd03cbe7a",
              "afbed34921e342029bd6d63aa25266d2537bf44592ab3428b1c4a8c9ff80f6a9"
                  + "21021b2b464d17c42f5484494fc8e62744bc5f14546be924e7260e2f94c1198501",
              "041e06278c28426cdc7e987488637aa9d555608a0ecefc5619e073f6ac48ae0760"
                  + "2d84f12ff7ff5ac1a5266e0cab280e181b1f886f75bd0e7565056cee079f2d4c",
              "021e06278c28426cdc7e987488637aa9d555608a0ecefc5619e073f6ac48ae0760"),
          vector(
              "keccak key 2",
              "5f1b94249f60809342da726cec530c7133a77dcbed72667722d5d994959bd275",
              "7994151c6b122a0bfac5f42b6c46df522f06f61ef5a57439ce644f9569a6c353",
              "510341e4bc76fb9a17ebbbbe01b9aa1f461558c76d5150c9fe802f4f4b4683c7"
                  + "3d54979ebaa0dc07468161d6479f3f8542710db67af2a68fbef422861a9b1efc00",
              "044793656a62b92f789e441ed316ab36ae548b16a2e9879c5531249f1bcfcd58ba"
                  + "e7f7046245013eada124a80b7a569318397631d99f810cecadac739d7509e8e4",
              "024793656a62b92f789e441ed316ab36ae548b16a2e9879c5531249f1bcfcd58ba"),
          vector(
              "keccak key 3",
              "c775035f74a58828f4597f2e262e5afdb2ac70a26515d12ffda581858eba0322",
              "2096ca159c94a7d790b46e93ebc5db8cc2a3ac19a95fac4314b6d9fb85333d37",
              "9539ca18d121f2852c42beb18dfe23890bd3a1b7a2d58c82e5cd45d7766e60a3"
                  + "63899f24b07b8901420f8a1f163fb2c9f178b8d8d5c6de94716957342f5272ab00",
              "048683b36354ec26d235ed2e8747503feb6394a7e3d919dd8c3df86a544dfafcf1"
                  + "b706cc2f54d64651a6acffbe4aee3c2e166faffcbbc8a2b240b8c48405aa2c7a",
              "028683b36354ec26d235ed2e8747503feb6394a7e3d919dd8c3df86a544dfafcf1"));

  /** The first vector, for tests that only need one valid input. */
  static final Vector VECTOR = VECTORS.get(0);

  private Secp256k1TestVectors() {}

  private static Vector vector(
      final String name,
      final String privateKey,
      final String messageHash,
      final String signature,
      final String publicKey,
      final String compressedPublicKey) {
    return new Vector(
        name,
        hex(privateKey),
        hex(messageHash),
        hex(signature),
        hex(publicKey),
        hex(compressedPublicKey));
  }

  static byte[] hex(final String hex) {
    return Bytes.fromHexString(hex).toArrayUnsafe();
  }

  /** The value, which must be below 2^256, as 32 big-endian bytes. */
  static byte[] bytes32(final BigInteger value) {
    final byte[] bytes = value.toByteArray();
    final int length = Math.min(bytes.length, 32);
    final byte[] result = new byte[32];
    System.arraycopy(bytes, bytes.length - length, result, 32 - length, length);
    return result;
  }

  /** r || s of two 256-bit values. */
  static byte[] signature(final BigInteger r, final BigInteger s) {
    final byte[] signature = new byte[64];
    System.arraycopy(bytes32(r), 0, signature, 0, 32);
    System.arraycopy(bytes32(s), 0, signature, 32, 32);
    return signature;
  }

  static BigInteger r(final byte[] signature) {
    return new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
  }

  static BigInteger s(final byte[] signature) {
    return new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
  }

  static byte[] sentinel(final int length) {
    final byte[] buffer = new byte[length];
    Arrays.fill(buffer, (byte) 0x55);
    return buffer;
  }
}
