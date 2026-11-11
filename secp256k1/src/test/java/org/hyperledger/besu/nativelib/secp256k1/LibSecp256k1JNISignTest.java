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
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_ERROR;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_FAIL;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_SUCCESS;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ec_pubkey_create_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_sign_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_verify_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecrecover_jni;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.N;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTOR;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTORS;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.bytes32;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.s;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.sentinel;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.Vector;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/** Also runs with -Dsecp256k1.randomize=false, see the testWithoutRandomization task. */
public class LibSecp256k1JNISignTest {

  @Before
  public void requireNative() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);
  }

  @Test
  public void signsTheFixedVectors() {
    for (final Vector vector : VECTORS) {
      final byte[] signature = new byte[65];
      assertThat(secp256k1_ecdsa_sign_jni(vector.messageHash(), vector.privateKey(), signature))
          .as(vector.name())
          .isEqualTo(STATUS_SUCCESS);
      assertThat(signature).as(vector.name()).isEqualTo(vector.signature());
    }
  }

  @Test
  public void signaturesRecoverAndVerifyWithTheSigningKey() {
    final Random random = new Random(1);
    for (int i = 0; i < 200; i++) {
      final byte[] privateKey = bytes32(new BigInteger(256, random).mod(N.subtract(ONE)).add(ONE));
      final byte[] messageHash = new byte[32];
      random.nextBytes(messageHash);

      final byte[] signature = new byte[65];
      assertThat(secp256k1_ecdsa_sign_jni(messageHash, privateKey, signature))
          .isEqualTo(STATUS_SUCCESS);
      assertThat(s(signature)).isLessThanOrEqualTo(N.shiftRight(1));
      final byte[] compactSignature = Arrays.copyOf(signature, 64);

      final byte[] publicKey = new byte[65];
      assertThat(secp256k1_ec_pubkey_create_jni(privateKey, publicKey)).isEqualTo(STATUS_SUCCESS);
      final byte[] recovered = new byte[65];
      assertThat(secp256k1_ecrecover_jni(messageHash, compactSignature, signature[64], recovered))
          .isEqualTo(0);
      assertThat(recovered).isEqualTo(publicKey);
      assertThat(
              secp256k1_ecdsa_verify_jni(
                  messageHash, compactSignature, Arrays.copyOfRange(publicKey, 1, 65)))
          .isEqualTo(STATUS_SUCCESS);
    }
  }

  @Test
  public void rejectsPrivateKeysThatAreZeroOrNotBelowTheCurveOrder() {
    for (final BigInteger privateKey : List.of(ZERO, N, N.add(ONE), TWO.pow(256).subtract(ONE))) {
      final byte[] signature = sentinel(65);
      assertThat(secp256k1_ecdsa_sign_jni(VECTOR.messageHash(), bytes32(privateKey), signature))
          .as(privateKey.toString(16))
          .isEqualTo(STATUS_FAIL);
      assertThat(signature).as(privateKey.toString(16)).isEqualTo(sentinel(65));
    }
  }

  @Test
  public void signsConcurrentlyWithTheSharedContext() throws Exception {
    final int threads = 8;
    final ExecutorService executor = Executors.newFixedThreadPool(threads);
    try {
      final List<Future<?>> results = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        results.add(
            executor.submit(
                () -> {
                  for (int i = 0; i < 100; i++) {
                    for (final Vector vector : VECTORS) {
                      final byte[] signature = new byte[65];
                      assertThat(
                              secp256k1_ecdsa_sign_jni(
                                  vector.messageHash(), vector.privateKey(), signature))
                          .isEqualTo(STATUS_SUCCESS);
                      assertThat(signature).as(vector.name()).isEqualTo(vector.signature());
                    }
                  }
                  return null;
                }));
      }
      for (final Future<?> result : results) {
        result.get(1, TimeUnit.MINUTES);
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  public void signingContextCanNotBeReplaced() throws Exception {
    final Method initSigningContext =
        LibSecp256k1JNI.class.getDeclaredMethod("initSigningContext", byte[].class);
    initSigningContext.setAccessible(true);

    assertThat(initSigningContext.invoke(null, (Object) new byte[32])).isEqualTo(STATUS_ERROR);
    assertThat(initSigningContext.invoke(null, (Object) null)).isEqualTo(STATUS_ERROR);
    signsTheFixedVectors();
  }
}
