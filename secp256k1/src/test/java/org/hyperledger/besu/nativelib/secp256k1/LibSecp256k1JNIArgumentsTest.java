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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.STATUS_ERROR;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ec_pubkey_create_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ec_pubkey_parse_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdh_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_sign_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_signature_normalize_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecdsa_verify_jni;
import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1JNI.secp256k1_ecrecover_jni;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.VECTOR;
import static org.hyperledger.besu.nativelib.secp256k1.Secp256k1TestVectors.sentinel;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

/**
 * Arrays that are null or have the wrong length must give an error code, not a crash or a write
 * outside the array, and must leave the output buffer unchanged, except ECDH, which clears it.
 */
public class LibSecp256k1JNIArgumentsTest {

  private static final byte[] HASH = VECTOR.messageHash();
  private static final byte[] PRIVATE_KEY = VECTOR.privateKey();
  private static final byte[] SIGNATURE = VECTOR.compactSignature();
  private static final byte[] PUBLIC_KEY = VECTOR.rawPublicKey();

  @Before
  public void requireNative() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);
  }

  @Test
  public void sign() {
    for (final byte[] invalid : invalid(32)) {
      expectUnchangedOutput(
          65, STATUS_ERROR, out -> secp256k1_ecdsa_sign_jni(invalid, PRIVATE_KEY, out), invalid);
      expectUnchangedOutput(
          65, STATUS_ERROR, out -> secp256k1_ecdsa_sign_jni(HASH, invalid, out), invalid);
    }
    expectInvalidOutput(
        invalid(65), STATUS_ERROR, out -> secp256k1_ecdsa_sign_jni(HASH, PRIVATE_KEY, out));
  }

  @Test
  public void verify() {
    for (final byte[] invalid : invalid(32)) {
      assertThat(secp256k1_ecdsa_verify_jni(invalid, SIGNATURE, PUBLIC_KEY))
          .as(describe(invalid))
          .isEqualTo(STATUS_ERROR);
    }
    for (final byte[] invalid : invalid(64)) {
      assertThat(secp256k1_ecdsa_verify_jni(HASH, invalid, PUBLIC_KEY))
          .as(describe(invalid))
          .isEqualTo(STATUS_ERROR);
      assertThat(secp256k1_ecdsa_verify_jni(HASH, SIGNATURE, invalid))
          .as(describe(invalid))
          .isEqualTo(STATUS_ERROR);
    }
    // the 65-byte encoding of a signature, with the recovery id, is not accepted either
    assertThat(secp256k1_ecdsa_verify_jni(HASH, VECTOR.signature(), PUBLIC_KEY))
        .isEqualTo(STATUS_ERROR);
    assertThat(secp256k1_ecdsa_verify_jni(HASH, SIGNATURE, VECTOR.publicKey()))
        .isEqualTo(STATUS_ERROR);
  }

  @Test
  public void normalize() {
    for (final byte[] invalid : invalid(64)) {
      expectUnchangedOutput(
          64, STATUS_ERROR, out -> secp256k1_ecdsa_signature_normalize_jni(invalid, out), invalid);
    }
    expectInvalidOutput(
        invalid(64), STATUS_ERROR, out -> secp256k1_ecdsa_signature_normalize_jni(SIGNATURE, out));
  }

  @Test
  public void createPublicKey() {
    for (final byte[] invalid : invalid(32)) {
      for (final int length : new int[] {33, 65}) {
        expectUnchangedOutput(
            length, STATUS_ERROR, out -> secp256k1_ec_pubkey_create_jni(invalid, out), invalid);
      }
    }
    expectInvalidOutput(
        invalidPublicKeys(), STATUS_ERROR, out -> secp256k1_ec_pubkey_create_jni(PRIVATE_KEY, out));
  }

  @Test
  public void parsePublicKey() {
    for (final byte[] invalid : invalidPublicKeys()) {
      for (final int length : new int[] {33, 65}) {
        expectUnchangedOutput(
            length, STATUS_ERROR, out -> secp256k1_ec_pubkey_parse_jni(invalid, out), invalid);
      }
    }
    expectInvalidOutput(
        invalidPublicKeys(),
        STATUS_ERROR,
        out -> secp256k1_ec_pubkey_parse_jni(VECTOR.publicKey(), out));
  }

  @Test
  public void ecrecover() {
    for (final byte[] invalid : invalid(32)) {
      expectUnchangedOutput(
          65,
          1,
          out -> secp256k1_ecrecover_jni(invalid, SIGNATURE, VECTOR.recoveryId(), out),
          invalid);
    }
    for (final byte[] invalid : invalid(64)) {
      expectUnchangedOutput(
          65, 1, out -> secp256k1_ecrecover_jni(HASH, invalid, VECTOR.recoveryId(), out), invalid);
    }
    expectInvalidOutput(
        invalid(65), 1, out -> secp256k1_ecrecover_jni(HASH, SIGNATURE, VECTOR.recoveryId(), out));
  }

  @Test
  public void ecdh() {
    for (final byte[] invalid : invalid(64)) {
      expectClearedOutput(out -> secp256k1_ecdh_jni(invalid, PRIVATE_KEY, out), invalid);
    }
    for (final byte[] invalid : invalid(32)) {
      expectClearedOutput(out -> secp256k1_ecdh_jni(PUBLIC_KEY, invalid, out), invalid);
    }
    expectInvalidOutput(invalid(33), 1, out -> secp256k1_ecdh_jni(PUBLIC_KEY, PRIVATE_KEY, out));
  }

  /** null, empty, one byte short and one byte long. */
  private static List<byte[]> invalid(final int length) {
    return Arrays.asList(null, new byte[0], new byte[length - 1], new byte[length + 1]);
  }

  /** Neither 33 nor 65 bytes. */
  private static List<byte[]> invalidPublicKeys() {
    return Arrays.asList(null, new byte[0], new byte[32], new byte[34], new byte[64], new byte[66]);
  }

  private static void expectUnchangedOutput(
      final int outputLength,
      final int expectedStatus,
      final Function<byte[], Integer> call,
      final byte[] invalid) {
    final byte[] output = sentinel(outputLength);
    assertThat(call.apply(output)).as(describe(invalid)).isEqualTo(expectedStatus);
    assertThat(output).as(describe(invalid)).isEqualTo(sentinel(outputLength));
  }

  private static void expectClearedOutput(
      final Function<byte[], Integer> call, final byte[] invalid) {
    final byte[] output = sentinel(33);
    assertThat(call.apply(output)).as(describe(invalid)).isEqualTo(1);
    assertThat(output).as(describe(invalid)).containsOnly((byte) 0);
  }

  private static void expectInvalidOutput(
      final List<byte[]> outputs, final int expectedStatus, final Function<byte[], Integer> call) {
    for (final byte[] output : outputs) {
      final byte[] before = output == null ? null : output.clone();
      assertThat(call.apply(output)).as("output " + describe(output)).isEqualTo(expectedStatus);
      assertThat(output).as("output " + describe(output)).isEqualTo(before);
    }
  }

  private static String describe(final byte[] array) {
    return array == null ? "null" : array.length + " bytes";
  }
}
