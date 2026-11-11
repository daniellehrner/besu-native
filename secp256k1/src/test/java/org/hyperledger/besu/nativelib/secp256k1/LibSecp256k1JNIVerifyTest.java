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
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_UNPARSEABLE_SIGNATURE;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_signature_normalize_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_verify_jni;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.N;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.P;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTOR;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTORS;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.bytes32;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.r;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.s;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.sentinel;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.signature;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.Vector;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

public class LibSecp256k1JNIVerifyTest {

  private static final BigInteger MAX_256 = TWO.pow(256).subtract(ONE);

  @Before
  public void requireNative() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);
  }

  @Test
  public void acceptsTheFixedVectors() {
    for (final Vector vector : VECTORS) {
      assertThat(verify(vector.messageHash(), vector.compactSignature(), vector.rawPublicKey()))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
    }
  }

  @Test
  public void rejectsTheSignatureWithTheHighS() {
    for (final Vector vector : VECTORS) {
      final byte[] signature = vector.compactSignature();
      final byte[] highS = signature(r(signature), N.subtract(s(signature)));
      assertThat(verify(vector.messageHash(), highS, vector.rawPublicKey()))
          .as(vector.name())
          .isEqualTo(STATUS_FAIL);
    }
  }

  @Test
  public void rejectsAnotherKeyOrHash() {
    final Vector other = VECTORS.get(1);
    assertThat(verify(VECTOR.messageHash(), VECTOR.compactSignature(), other.rawPublicKey()))
        .isEqualTo(STATUS_FAIL);
    assertThat(verify(other.messageHash(), VECTOR.compactSignature(), VECTOR.rawPublicKey()))
        .isEqualTo(STATUS_FAIL);
  }

  @Test
  public void rejectsZeroROrS() {
    final byte[] signature = VECTOR.compactSignature();
    for (final byte[] zero :
        List.of(signature(ZERO, s(signature)), signature(r(signature), ZERO), new byte[64])) {
      assertThat(verify(VECTOR.messageHash(), zero, VECTOR.rawPublicKey())).isEqualTo(STATUS_FAIL);
    }
  }

  @Test
  public void cannotParseROrSNotBelowTheCurveOrder() {
    final byte[] signature = VECTOR.compactSignature();
    for (final byte[] unparseable :
        List.of(
            signature(N, s(signature)),
            signature(r(signature), N),
            signature(MAX_256, s(signature)),
            signature(r(signature), MAX_256))) {
      assertThat(verify(VECTOR.messageHash(), unparseable, VECTOR.rawPublicKey()))
          .isEqualTo(STATUS_UNPARSEABLE_SIGNATURE);
    }
  }

  @Test
  public void cannotParsePublicKeysThatAreNotOnTheCurve() {
    final byte[] yPlusOne = VECTOR.rawPublicKey();
    yPlusOne[63]++;
    final byte[] xIsP = VECTOR.rawPublicKey();
    System.arraycopy(bytes32(P), 0, xIsP, 0, 32);

    for (final byte[] publicKey : List.of(yPlusOne, xIsP, new byte[64])) {
      assertThat(verify(VECTOR.messageHash(), VECTOR.compactSignature(), publicKey))
          .isEqualTo(STATUS_UNPARSEABLE_PUBLIC_KEY);
    }
  }

  @Test
  public void reportsAnUnparseableSignatureBeforeAnUnparseablePublicKey() {
    assertThat(verify(VECTOR.messageHash(), signature(N, ONE), new byte[64]))
        .isEqualTo(STATUS_UNPARSEABLE_SIGNATURE);
  }

  @Test
  public void acceptsASignatureWhoseRIsTheXCoordinateMinusTheCurveOrder() {
    final byte[] signature = Arrays.copyOf(LibSecp256k1JNIRecoveryIdTest.SIGNATURE, 64);
    for (final int recoveryId : new int[] {2, 3}) {
      final byte[] publicKey =
          Arrays.copyOfRange(LibSecp256k1JNIRecoveryIdTest.RECOVERED[recoveryId], 1, 65);
      assertThat(verify(LibSecp256k1JNIRecoveryIdTest.MESSAGE_HASH, signature, publicKey))
          .as("recovery id %d", recoveryId)
          .isEqualTo(STATUS_SUCCESS);
    }
  }

  @Test
  public void normalizesTheHighS() {
    for (final Vector vector : VECTORS) {
      final byte[] signature = vector.compactSignature();
      final byte[] highS = signature(r(signature), N.subtract(s(signature)));

      final byte[] normalized = new byte[64];
      assertThat(secp256k1_ecdsa_signature_normalize_jni(highS, normalized))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(normalized).as(vector.name()).isEqualTo(signature);

      // in place
      assertThat(secp256k1_ecdsa_signature_normalize_jni(highS, highS)).isEqualTo(STATUS_SUCCESS);
      assertThat(highS).as(vector.name()).isEqualTo(signature);
    }
  }

  @Test
  public void keepsTheLowS() {
    for (final Vector vector : VECTORS) {
      final byte[] normalized = new byte[64];
      assertThat(secp256k1_ecdsa_signature_normalize_jni(vector.compactSignature(), normalized))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(normalized).as(vector.name()).isEqualTo(vector.compactSignature());
    }
  }

  @Test
  public void cannotNormalizeROrSNotBelowTheCurveOrder() {
    for (final byte[] unparseable : List.of(signature(N, ONE), signature(ONE, N))) {
      final byte[] normalized = sentinel(64);
      assertThat(secp256k1_ecdsa_signature_normalize_jni(unparseable, normalized))
          .isEqualTo(STATUS_UNPARSEABLE_SIGNATURE);
      assertThat(normalized).isEqualTo(sentinel(64));
    }
  }

  private static int verify(
      final byte[] messageHash, final byte[] signature, final byte[] publicKey) {
    return secp256k1_ecdsa_verify_jni(messageHash, signature, publicKey);
  }
}
