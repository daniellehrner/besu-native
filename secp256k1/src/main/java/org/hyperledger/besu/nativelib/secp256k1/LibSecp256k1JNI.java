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

import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

/**
 * secp256k1 operations of libsecp256k1, bound with JNI. All functions take and return byte arrays
 * and are thread-safe.
 */
public class LibSecp256k1JNI {

  /** Whether the native library is loaded and its signing context was created. */
  public static final boolean ENABLED;

  /** The operation succeeded, or the signature is valid. */
  public static final int STATUS_SUCCESS = 0;

  /** The operation failed, or the signature is not valid. */
  public static final int STATUS_FAIL = 1;

  /**
   * An argument is invalid: in the native functions an array that is null or has the wrong length,
   * in the {@link #ecrecover} and {@link #ecdh} wrappers any input they reject.
   */
  public static final int STATUS_ERROR = 2;

  /** The signature can't be parsed, because r or s is not below the curve order. */
  public static final int STATUS_UNPARSEABLE_SIGNATURE = 3;

  /** The public key can't be parsed, because it is not a point on the curve. */
  public static final int STATUS_UNPARSEABLE_PUBLIC_KEY = 4;

  // secp256k1 curve order
  private static final BigInteger SECP256K1_ORDER =
      new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.loadJNI(LibSecp256k1JNI.class, "secp256k1_ecrecover");
      final byte[] seed = signingContextSeed();
      try {
        if (initSigningContext(seed) != STATUS_SUCCESS) {
          throw new IllegalStateException("Could not create the secp256k1 signing context");
        }
      } finally {
        if (seed != null) {
          Arrays.fill(seed, (byte) 0);
        }
      }
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  // The seed blinds the signing context against side channels, unless -Dsecp256k1.randomize=false
  private static byte[] signingContextSeed() throws NoSuchAlgorithmException {
    if (!Boolean.parseBoolean(System.getProperty("secp256k1.randomize", "true"))) {
      return null;
    }
    final byte[] seed = new byte[32];
    SecureRandom.getInstanceStrong().nextBytes(seed);
    return seed;
  }

  /**
   * Creates the context for signing and public key creation. Only the static initializer calls
   * this, once, because the context must not change while other threads use it.
   *
   * @param seed 32 random bytes to randomize the context with, or null to leave it unrandomized
   * @return {@link #STATUS_SUCCESS}, {@link #STATUS_FAIL} if the context could not be created or
   *     randomized, or {@link #STATUS_ERROR} if the seed has the wrong length or the context
   *     already exists
   */
  private static native int initSigningContext(byte[] seed);

  /**
   * Creates a recoverable ECDSA signature with the deterministic nonce of RFC 6979, so the same
   * hash and key always give the same signature. s is always in the lower half of the curve order.
   *
   * @param messageHash  the 32-byte message hash to sign
   * @param privateKey   the 32-byte private key
   * @param outputBuffer the 65-byte output buffer for r || s || recovery id, written only on
   *                     success. The recovery id is 0 to 3, though 2 and 3 practically never occur.
   * @return {@link #STATUS_SUCCESS}, {@link #STATUS_FAIL} if the private key is zero or not below
   *     the curve order, or {@link #STATUS_ERROR} if an array is null or has the wrong length or
   *     the signing context could not be created
   */
  public static native int secp256k1_ecdsa_sign_jni(byte[] messageHash, byte[] privateKey,
      byte[] outputBuffer);

  /**
   * Verifies an ECDSA signature. The signature is not normalized, so a signature whose s is above
   * half the curve order is not valid.
   *
   * @param messageHash the 32-byte message hash that was signed
   * @param signature   the 64-byte compact signature (r || s)
   * @param publicKey   the 64-byte uncompressed public key (x || y, without the 0x04 prefix)
   * @return {@link #STATUS_SUCCESS} if the signature is valid, {@link #STATUS_FAIL} if it is not,
   *     {@link #STATUS_UNPARSEABLE_SIGNATURE} if r or s is not below the curve order,
   *     {@link #STATUS_UNPARSEABLE_PUBLIC_KEY} if the public key is not a point on the curve, or
   *     {@link #STATUS_ERROR} if an array is null or has the wrong length
   */
  public static native int secp256k1_ecdsa_verify_jni(byte[] messageHash, byte[] signature,
      byte[] publicKey);

  /**
   * Converts a signature to the form with s in the lower half of the curve order, which is the
   * only form {@link #secp256k1_ecdsa_verify_jni} accepts.
   *
   * @param signature    the 64-byte compact signature (r || s)
   * @param outputBuffer the 64-byte output buffer for the normalized signature, written only on
   *                     success. It may be the signature array.
   * @return {@link #STATUS_SUCCESS}, {@link #STATUS_UNPARSEABLE_SIGNATURE} if r or s is not below
   *     the curve order, or {@link #STATUS_ERROR} if an array is null or has the wrong length
   */
  public static native int secp256k1_ecdsa_signature_normalize_jni(byte[] signature,
      byte[] outputBuffer);

  /**
   * Computes the public key of a private key.
   *
   * @param privateKey   the 32-byte private key
   * @param outputBuffer the output buffer for the public key, written only on success. Its length
   *                     selects the format: 33 bytes compressed, 65 bytes uncompressed (0x04 || x
   *                     || y).
   * @return {@link #STATUS_SUCCESS}, {@link #STATUS_FAIL} if the private key is zero or not below
   *     the curve order, or {@link #STATUS_ERROR} if an array is null or has the wrong length or
   *     the signing context could not be created
   */
  public static native int secp256k1_ec_pubkey_create_jni(byte[] privateKey,
      byte[] outputBuffer);

  /**
   * Parses a serialized public key and serializes it again, e.g. to decompress it.
   *
   * @param publicKey    the public key, 33 bytes compressed (0x02 or 0x03 || x) or 65 bytes
   *                     uncompressed (0x04 || x || y) or hybrid (0x06 or 0x07 || x || y)
   * @param outputBuffer the output buffer for the public key, written only on success. Its length
   *                     selects the format: 33 bytes compressed, 65 bytes uncompressed.
   * @return {@link #STATUS_SUCCESS}, {@link #STATUS_UNPARSEABLE_PUBLIC_KEY} if the public key is
   *     not a point on the curve or not encoded correctly, or {@link #STATUS_ERROR} if an array is
   *     null or has the wrong length
   */
  public static native int secp256k1_ec_pubkey_parse_jni(byte[] publicKey, byte[] outputBuffer);

  /**
   * Consolidated ECRECOVER operation in a single native call.
   *
   * <p>Unlike {@link #ecrecover}, this accepts recovery ids 2 and 3, which select the point whose x
   * coordinate is r plus the curve order. That point only exists if r is below the field prime
   * minus the curve order.
   *
   * @param messageHash  the 32-byte message hash that was signed
   * @param signature    the 64-byte compact signature (r || s)
   * @param recoveryId   the recovery ID (0, 1, 2, or 3)
   * @param outputBuffer the 65-byte output buffer for the recovered uncompressed public key (0x04
   *                     || x || y), written only on success
   * @return 0 if recovery was successful, 1 otherwise, including for an array that is null or has
   *     the wrong length
   */
  public static native int secp256k1_ecrecover_jni(byte[] messageHash, byte[] signature,
      int recoveryId, byte[] outputBuffer);

  /**
   * Result wrapper for ECRECOVER operations
   */
  public record ECRecoverResult(int status, Optional<byte[]> publicKey, Optional<String> error) {
  }

  /**
   * Safe wrapper for the native ECRECOVER operation.
   *
   * @param messageHash the 32-byte message hash that was signed
   * @param signature   the 64-byte compact signature (r || s)
   * @param recoveryId  the recovery ID (0, 1)
   * @return ECRecoverResult containing success status and recovered public key
   */
  public static ECRecoverResult ecrecover(byte[] messageHash, byte[] signature, int recoveryId) {
    if (messageHash == null || messageHash.length != 32) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("messageHash must be 32 bytes"));
    }
    if (signature == null || signature.length != 64) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("signature must be 64 bytes"));
    }
    if (recoveryId < 0 || recoveryId > 1) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("recoveryId " + recoveryId + " must be either 0 or 1"));
    }

    // Extract r and s values
    byte[] rBytes = new byte[32];
    byte[] sBytes = new byte[32];
    System.arraycopy(signature, 0, rBytes, 0, 32);
    System.arraycopy(signature, 32, sBytes, 0, 32);

    BigInteger r = new BigInteger(1, rBytes);
    BigInteger s = new BigInteger(1, sBytes);

    // Validate r and s are in range [1, n-1] before calling native method
    if (r.equals(BigInteger.ZERO) || r.compareTo(SECP256K1_ORDER) >= 0) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid signature r value"));
    }

    if (s.equals(BigInteger.ZERO) || s.compareTo(SECP256K1_ORDER) >= 0) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid signature s value"));
    }


    byte[] outputBuffer = new byte[65]; // uncompressed public key format
    int result = secp256k1_ecrecover_jni(messageHash, signature, recoveryId, outputBuffer);

    if (result == 0) {
      // Strip the 0x04 prefix to get the 64-byte public key
      byte[] publicKey = new byte[64];
      System.arraycopy(outputBuffer, 1, publicKey, 0, 64);
      return new ECRecoverResult(STATUS_SUCCESS, Optional.of(publicKey), Optional.empty());
    } else {
      return new ECRecoverResult(STATUS_FAIL, Optional.empty(), Optional.of("failed to recover"));
    }
  }

  /**
   * ECDH key agreement in a single native call, computed in constant time.
   *
   * <p>The shared point is returned unhashed so that callers can apply their protocol's key
   * derivation, e.g. RLPx uses the x coordinate and discv5 the compressed point.
   *
   * @param publicKey    the 64-byte uncompressed public key (x || y, without the 0x04 prefix)
   * @param privateKey   the 32-byte private key
   * @param outputBuffer the output buffer for the 33-byte compressed shared point, whose x
   *                     coordinate is bytes 1 to 32. It is cleared on failure if it has 33
   *                     bytes.
   * @return 0 if the agreement was successful, 1 otherwise, including for an array that is null or
   *     has the wrong length
   */
  public static native int secp256k1_ecdh_jni(byte[] publicKey, byte[] privateKey,
      byte[] outputBuffer);

  /**
   * Result wrapper for ECDH operations
   */
  public record ECDHResult(int status, Optional<byte[]> sharedPoint, Optional<String> error) {
  }

  /**
   * Safe wrapper for the native ECDH operation.
   *
   * @param publicKey  the 64-byte uncompressed public key (x || y)
   * @param privateKey the 32-byte private key, which must be non-zero and below the curve order
   * @return ECDHResult containing the 33-byte compressed shared point on success
   */
  public static ECDHResult ecdh(byte[] publicKey, byte[] privateKey) {
    if (publicKey == null || publicKey.length != 64) {
      return new ECDHResult(STATUS_ERROR, Optional.empty(),
          Optional.of("publicKey must be 64 bytes"));
    }
    if (privateKey == null || privateKey.length != 32) {
      return new ECDHResult(STATUS_ERROR, Optional.empty(),
          Optional.of("privateKey must be 32 bytes"));
    }

    byte[] outputBuffer = new byte[33];
    int result = secp256k1_ecdh_jni(publicKey, privateKey, outputBuffer);

    if (result == 0) {
      return new ECDHResult(STATUS_SUCCESS, Optional.of(outputBuffer), Optional.empty());
    } else {
      return new ECDHResult(STATUS_FAIL, Optional.empty(),
          Optional.of("invalid public key or private key"));
    }
  }
}
