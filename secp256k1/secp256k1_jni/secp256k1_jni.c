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
#include <jni.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "secp256k1_ecrecover.h"

// The values of the STATUS_ constants in LibSecp256k1JNI
#define STATUS_SUCCESS 0
#define STATUS_FAIL 1
#define STATUS_ERROR 2
#define STATUS_UNPARSEABLE_SIGNATURE 3
#define STATUS_UNPARSEABLE_PUBLIC_KEY 4

// The static context can't sign. This one is created and randomized once while LibSecp256k1JNI
// initializes and never changed afterwards, because secp256k1_context_randomize needs exclusive
// access and signing runs on many threads at once.
static secp256k1_context *signing_context = NULL;

// The barrier keeps the compiler from dropping the memset of a buffer that is not read again
static void clear(void *buffer, size_t length) {
    memset(buffer, 0, length);
    __asm__ __volatile__("" : : "r"(buffer) : "memory");
}

static int has_length(JNIEnv *env, jbyteArray array, jsize length) {
    return array != NULL && (*env)->GetArrayLength(env, array) == length;
}

// Copies the array, which must not be null and must have exactly length bytes
static int read_array(JNIEnv *env, jbyteArray array, unsigned char *buffer, jsize length) {
    if (!has_length(env, array, length)) {
        return 0;
    }
    (*env)->GetByteArrayRegion(env, array, 0, length, (jbyte *) buffer);
    return 1;
}

static void write_array(JNIEnv *env, jbyteArray array, const unsigned char *buffer, jsize length) {
    (*env)->SetByteArrayRegion(env, array, 0, length, (const jbyte *) buffer);
}

// The length of the output array selects the format: 33 bytes compressed, 65 bytes uncompressed
static int public_key_format(JNIEnv *env, jbyteArray array, size_t *length, unsigned int *flags) {
    if (array == NULL) {
        return 0;
    }
    switch ((*env)->GetArrayLength(env, array)) {
        case 33:
            *length = 33;
            *flags = SECP256K1_EC_COMPRESSED;
            return 1;
        case 65:
            *length = 65;
            *flags = SECP256K1_EC_UNCOMPRESSED;
            return 1;
        default:
            return 0;
    }
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_initSigningContext(
    JNIEnv *env, jclass clazz, jbyteArray seed) {
    (void) clazz;
    unsigned char seed32[32];
    int status = STATUS_SUCCESS;

    if (signing_context != NULL) {
        return STATUS_ERROR;
    }
    if (seed != NULL && !read_array(env, seed, seed32, 32)) {
        return STATUS_ERROR;
    }

    secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context == NULL) {
        status = STATUS_FAIL;
    } else if (seed != NULL && secp256k1_context_randomize(context, seed32) != 1) {
        secp256k1_context_destroy(context);
        status = STATUS_FAIL;
    } else {
        signing_context = context;
    }

    clear(seed32, sizeof(seed32));
    return status;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ecdsa_1sign_1jni(
    JNIEnv *env, jclass clazz, jbyteArray message_hash, jbyteArray private_key,
    jbyteArray output_buffer) {
    (void) clazz;
    unsigned char hash[32];
    unsigned char seckey[32];
    unsigned char output[65];
    secp256k1_ecdsa_recoverable_signature signature;
    int recovery_id;

    if (signing_context == NULL || !has_length(env, output_buffer, 65)
        || !read_array(env, message_hash, hash, 32)
        || !read_array(env, private_key, seckey, 32)) {
        return STATUS_ERROR;
    }

    // the NULL nonce function is RFC 6979, so signatures are deterministic
    int signed_ok = secp256k1_ecdsa_sign_recoverable(
        signing_context, &signature, hash, seckey, NULL, NULL);
    clear(seckey, sizeof(seckey));
    // fails only for a private key that is zero or not below the curve order
    if (signed_ok != 1) {
        return STATUS_FAIL;
    }

    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        signing_context, output, &recovery_id, &signature);
    output[64] = (unsigned char) recovery_id;
    write_array(env, output_buffer, output, 65);
    return STATUS_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ecdsa_1verify_1jni(
    JNIEnv *env, jclass clazz, jbyteArray message_hash, jbyteArray signature,
    jbyteArray public_key) {
    (void) clazz;
    unsigned char hash[32];
    unsigned char compact_signature[64];
    unsigned char serialized_public_key[65];
    secp256k1_ecdsa_signature parsed_signature;
    secp256k1_pubkey parsed_public_key;

    if (!read_array(env, message_hash, hash, 32)
        || !read_array(env, signature, compact_signature, 64)
        || !read_array(env, public_key, serialized_public_key + 1, 64)) {
        return STATUS_ERROR;
    }
    serialized_public_key[0] = 0x04;

    if (secp256k1_ecdsa_signature_parse_compact(
            secp256k1_context_static, &parsed_signature, compact_signature) != 1) {
        return STATUS_UNPARSEABLE_SIGNATURE;
    }
    if (secp256k1_ec_pubkey_parse(
            secp256k1_context_static, &parsed_public_key, serialized_public_key,
            sizeof(serialized_public_key)) != 1) {
        return STATUS_UNPARSEABLE_PUBLIC_KEY;
    }

    // not normalized, so a signature with an s above half the curve order is invalid
    return secp256k1_ecdsa_verify(
               secp256k1_context_static, &parsed_signature, hash, &parsed_public_key) == 1
        ? STATUS_SUCCESS
        : STATUS_FAIL;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ecdsa_1signature_1normalize_1jni(
    JNIEnv *env, jclass clazz, jbyteArray signature, jbyteArray output_buffer) {
    (void) clazz;
    unsigned char compact_signature[64];
    secp256k1_ecdsa_signature parsed_signature;

    if (!has_length(env, output_buffer, 64) || !read_array(env, signature, compact_signature, 64)) {
        return STATUS_ERROR;
    }
    if (secp256k1_ecdsa_signature_parse_compact(
            secp256k1_context_static, &parsed_signature, compact_signature) != 1) {
        return STATUS_UNPARSEABLE_SIGNATURE;
    }

    secp256k1_ecdsa_signature_normalize(
        secp256k1_context_static, &parsed_signature, &parsed_signature);
    secp256k1_ecdsa_signature_serialize_compact(
        secp256k1_context_static, compact_signature, &parsed_signature);
    write_array(env, output_buffer, compact_signature, 64);
    return STATUS_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ec_1pubkey_1create_1jni(
    JNIEnv *env, jclass clazz, jbyteArray private_key, jbyteArray output_buffer) {
    (void) clazz;
    unsigned char seckey[32];
    unsigned char output[65];
    size_t output_length;
    unsigned int flags;
    secp256k1_pubkey public_key;

    // the static context can't multiply the generator
    if (signing_context == NULL || !public_key_format(env, output_buffer, &output_length, &flags)
        || !read_array(env, private_key, seckey, 32)) {
        return STATUS_ERROR;
    }

    int created = secp256k1_ec_pubkey_create(signing_context, &public_key, seckey);
    clear(seckey, sizeof(seckey));
    // fails only for a private key that is zero or not below the curve order
    if (created != 1) {
        return STATUS_FAIL;
    }

    secp256k1_ec_pubkey_serialize(
        secp256k1_context_static, output, &output_length, &public_key, flags);
    write_array(env, output_buffer, output, (jsize) output_length);
    return STATUS_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ec_1pubkey_1parse_1jni(
    JNIEnv *env, jclass clazz, jbyteArray public_key, jbyteArray output_buffer) {
    (void) clazz;
    unsigned char input[65];
    unsigned char output[65];
    size_t output_length;
    unsigned int flags;
    secp256k1_pubkey parsed_public_key;

    jsize input_length = public_key != NULL ? (*env)->GetArrayLength(env, public_key) : 0;
    if ((input_length != 33 && input_length != 65)
        || !read_array(env, public_key, input, input_length)
        || !public_key_format(env, output_buffer, &output_length, &flags)) {
        return STATUS_ERROR;
    }
    if (secp256k1_ec_pubkey_parse(
            secp256k1_context_static, &parsed_public_key, input, (size_t) input_length) != 1) {
        return STATUS_UNPARSEABLE_PUBLIC_KEY;
    }

    secp256k1_ec_pubkey_serialize(
        secp256k1_context_static, output, &output_length, &parsed_public_key, flags);
    write_array(env, output_buffer, output, (jsize) output_length);
    return STATUS_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ecrecover_1jni(
    JNIEnv *env, jclass clazz, jbyteArray message_hash, jbyteArray signature, jint recovery_id,
    jbyteArray output_buffer) {
    (void) clazz;
    unsigned char hash[32];
    unsigned char compact_signature[64];
    unsigned char output[65];

    if (!has_length(env, output_buffer, 65)
        || !read_array(env, message_hash, hash, 32)
        || !read_array(env, signature, compact_signature, 64)
        || secp256k1_ecrecover_jni(hash, compact_signature, recovery_id, output) != 0) {
        return STATUS_FAIL;
    }

    write_array(env, output_buffer, output, 65);
    return STATUS_SUCCESS;
}

JNIEXPORT jint JNICALL
Java_org_hyperledger_besu_nativelib_secp256k1_LibSecp256k1JNI_secp256k1_1ecdh_1jni(
    JNIEnv *env, jclass clazz, jbyteArray public_key, jbyteArray private_key,
    jbyteArray output_buffer) {
    (void) clazz;
    unsigned char serialized_public_key[64];
    unsigned char seckey[32];
    unsigned char output[33];
    int status = STATUS_FAIL;

    if (!has_length(env, output_buffer, 33)) {
        return STATUS_FAIL;
    }

    if (read_array(env, public_key, serialized_public_key, 64)
        && read_array(env, private_key, seckey, 32)
        && secp256k1_ecdh_jni(serialized_public_key, seckey, output) == 0) {
        status = STATUS_SUCCESS;
    } else {
        memset(output, 0, sizeof(output));
    }
    // also on failure, so that the buffer never keeps what the caller put there
    write_array(env, output_buffer, output, 33);

    clear(seckey, sizeof(seckey));
    clear(output, sizeof(output));
    return status;
}
