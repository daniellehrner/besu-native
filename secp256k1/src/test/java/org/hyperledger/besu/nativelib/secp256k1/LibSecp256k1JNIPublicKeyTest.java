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

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import static java.math.BigInteger.ZERO;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_FAIL;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_SUCCESS;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_UNPARSEABLE_PUBLIC_KEY;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ec_pubkey_create_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ec_pubkey_parse_jni;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.N;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.P;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTOR;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTORS;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.bytes32;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.sentinel;

import java.math.BigInteger;
import java.util.List;
import org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.Vector;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/** Also runs with -Dsecp256k1.randomize=false, see the testWithoutRandomization task. */
public class LibSecp256k1JNIPublicKeyTest {

  @Before
  public void requireNative() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);
  }

  @Test
  public void createsUncompressedAndCompressedPublicKeys() {
    for (final Vector vector : VECTORS) {
      final byte[] uncompressed = new byte[65];
      assertThat(secp256k1_ec_pubkey_create_jni(vector.privateKey(), uncompressed))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(uncompressed).as(vector.name()).isEqualTo(vector.publicKey());

      final byte[] compressed = new byte[33];
      assertThat(secp256k1_ec_pubkey_create_jni(vector.privateKey(), compressed))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(compressed).as(vector.name()).isEqualTo(vector.compressedPublicKey());
    }
  }

  @Test
  public void rejectsPrivateKeysThatAreZeroOrNotBelowTheCurveOrder() {
    for (final BigInteger privateKey : List.of(ZERO, N, N.add(ONE), TWO.pow(256).subtract(ONE))) {
      for (final int length : new int[] {33, 65}) {
        final byte[] publicKey = sentinel(length);
        assertThat(secp256k1_ec_pubkey_create_jni(bytes32(privateKey), publicKey))
            .as("%s into %d bytes", privateKey.toString(16), length)
            .isEqualTo(STATUS_FAIL);
        assertThat(publicKey).isEqualTo(sentinel(length));
      }
    }
  }

  @Test
  public void parsesAndSerializesInBothFormats() {
    for (final Vector vector : VECTORS) {
      for (final byte[] input : List.of(vector.publicKey(), vector.compressedPublicKey())) {
        final byte[] uncompressed = new byte[65];
        assertThat(secp256k1_ec_pubkey_parse_jni(input, uncompressed))
            .as(vector.name())
            .isEqualTo(STATUS_SUCCESS);
        assertThat(uncompressed).as(vector.name()).isEqualTo(vector.publicKey());

        final byte[] compressed = new byte[33];
        assertThat(secp256k1_ec_pubkey_parse_jni(input, compressed))
            .as(vector.name())
            .isEqualTo(STATUS_SUCCESS);
        assertThat(compressed).as(vector.name()).isEqualTo(vector.compressedPublicKey());
      }
    }
  }

  @Test
  public void parsesHybridKeysOnlyWithTheParityOfY() {
    for (final Vector vector : VECTORS) {
      final boolean odd = (vector.publicKey()[64] & 1) == 1;
      final byte[] hybrid = vector.publicKey().clone();

      hybrid[0] = (byte) (odd ? 0x07 : 0x06);
      final byte[] uncompressed = new byte[65];
      assertThat(secp256k1_ec_pubkey_parse_jni(hybrid, uncompressed))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(uncompressed).as(vector.name()).isEqualTo(vector.publicKey());

      hybrid[0] = (byte) (odd ? 0x06 : 0x07);
      assertThat(secp256k1_ec_pubkey_parse_jni(hybrid, new byte[65]))
          .as(vector.name())
          .isEqualTo(STATUS_UNPARSEABLE_PUBLIC_KEY);
    }
  }

  @Test
  public void rejectsKeysThatAreNotOnTheCurveOrNotEncodedCorrectly() {
    final byte[] yPlusOne = VECTOR.publicKey().clone();
    yPlusOne[64]++;

    final byte[] xIsP = new byte[65];
    xIsP[0] = 0x04;
    System.arraycopy(bytes32(P), 0, xIsP, 1, 32);
    System.arraycopy(VECTOR.publicKey(), 33, xIsP, 33, 32);

    final byte[] compressedXIsP = new byte[33];
    compressedXIsP[0] = 0x02;
    System.arraycopy(bytes32(P), 0, compressedXIsP, 1, 32);

    final byte[] compressedWithoutY = new byte[33];
    compressedWithoutY[0] = 0x02;
    System.arraycopy(bytes32(xWithoutPoint()), 0, compressedWithoutY, 1, 32);

    final byte[] compressedWithUncompressedPrefix = VECTOR.compressedPublicKey().clone();
    compressedWithUncompressedPrefix[0] = 0x04;
    final byte[] uncompressedWithCompressedPrefix = VECTOR.publicKey().clone();
    uncompressedWithCompressedPrefix[0] = 0x02;
    final byte[] uncompressedWithUnknownPrefix = VECTOR.publicKey().clone();
    uncompressedWithUnknownPrefix[0] = 0x05;

    for (final byte[] publicKey :
        List.of(
            yPlusOne,
            xIsP,
            compressedXIsP,
            compressedWithoutY,
            compressedWithUncompressedPrefix,
            uncompressedWithCompressedPrefix,
            uncompressedWithUnknownPrefix,
            new byte[33],
            new byte[65])) {
      for (final int length : new int[] {33, 65}) {
        final byte[] output = sentinel(length);
        assertThat(secp256k1_ec_pubkey_parse_jni(publicKey, output))
            .isEqualTo(STATUS_UNPARSEABLE_PUBLIC_KEY);
        assertThat(output).isEqualTo(sentinel(length));
      }
    }
  }

  // the smallest x for which x^3 + 7 is not a square, so no point has it as its x coordinate
  private static BigInteger xWithoutPoint() {
    final BigInteger exponent = P.subtract(ONE).shiftRight(1);
    BigInteger x = ONE;
    while (x.pow(3).add(BigInteger.valueOf(7)).modPow(exponent, P).equals(ONE)) {
      x = x.add(ONE);
    }
    return x;
  }
}
