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
import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_ERROR;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecrecover_jni;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.N;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.P;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.hex;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.s;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.sentinel;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.signature;

import java.math.BigInteger;
import java.util.List;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * Recovery ids 2 and 3 select the point whose x coordinate is r + n, which exists only for r below
 * p - n. r = 2 is the smallest r for which r + n is the x coordinate of a curve point. The
 * recovered keys were computed with BouncyCastle.
 */
public class LibSecp256k1JNIRecoveryIdTest {

  static final byte[] MESSAGE_HASH =
      hex("37e559c4b4c155aaf4eb0d35b0e549dc369aec030a69fa221754f4609cb9ddb7");
  static final byte[] SIGNATURE =
      hex(
          "0000000000000000000000000000000000000000000000000000000000000002"
              + "60a73bfb121a98fb6b52dfb29eb0defd76b60065b8cf07902baf28c167d24daf");
  static final byte[][] RECOVERED = {
    hex(
        "043ecdbe0f354dee4e72b317e2823471268348033e0ee58d108eda438778b60296"
            + "f11d462ebf6aaa894682829b1eeeb4833f5a029736c27759369603194b60c439"),
    hex(
        "04a9c5e2fc6f99a06c38cd5ad246e6e8a7f0b4a658133f4d187b555e90c7c03832"
            + "97b362baafc3287cf1bee2b8141f8edfd0c126159fa7069da02242f96dcb2530"),
    hex(
        "0423f45f0a373dddc06718469b1ebbf40ae9f67d90d41423a2fca8166b68c3a905"
            + "054da26541bb3e872db0552b2ab58be57e8405878392d2b729caf6d37584b250"),
    hex(
        "04e9415fe042fab4c671f89213c0cabe8050cbc39418b5e5662886a59b41425f1c"
            + "0aa1d1a5127de5579d87c56fbf75d119ef2683c63ec631de350ed588877ec321")
  };

  @Before
  public void requireNative() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);
  }

  @Test
  public void recoversWithAllFourRecoveryIds() {
    for (int recoveryId = 0; recoveryId < 4; recoveryId++) {
      final byte[] recovered = new byte[65];
      assertThat(secp256k1_ecrecover_jni(MESSAGE_HASH, SIGNATURE, recoveryId, recovered))
          .as("recovery id %d", recoveryId)
          .isEqualTo(0);
      assertThat(recovered).as("recovery id %d", recoveryId).isEqualTo(RECOVERED[recoveryId]);
    }
  }

  @Test
  public void recoveryIds2And3FailWhenRPlusTheCurveOrderIsNotBelowTheFieldPrime() {
    final BigInteger s = s(SIGNATURE);
    for (final BigInteger r : List.of(P.subtract(N), P.subtract(N).add(ONE), N.subtract(ONE))) {
      for (final int recoveryId : new int[] {2, 3}) {
        final byte[] recovered = sentinel(65);
        assertThat(secp256k1_ecrecover_jni(MESSAGE_HASH, signature(r, s), recoveryId, recovered))
            .as("r %s, recovery id %d", r.toString(16), recoveryId)
            .isEqualTo(1);
        assertThat(recovered).isEqualTo(sentinel(65));
      }
    }
  }

  @Test
  public void rejectsRecoveryIdsOutside0To3() {
    for (final int recoveryId : new int[] {-1, 4, 27, 28, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
      final byte[] recovered = sentinel(65);
      assertThat(secp256k1_ecrecover_jni(MESSAGE_HASH, SIGNATURE, recoveryId, recovered))
          .as("recovery id %d", recoveryId)
          .isEqualTo(1);
      assertThat(recovered).isEqualTo(sentinel(65));
    }
  }

  @Test
  public void ecrecoverWrapperStillRejectsRecoveryIds2And3() {
    for (final int recoveryId : new int[] {2, 3}) {
      final LibSecp256k1JNI.ECRecoverResult result =
          LibSecp256k1JNI.ecrecover(MESSAGE_HASH, SIGNATURE, recoveryId);
      assertThat(result.status()).isEqualTo(STATUS_ERROR);
      assertThat(result.publicKey()).isEmpty();
      assertThat(result.error()).hasValue("recoveryId " + recoveryId + " must be either 0 or 1");
    }
  }
}
