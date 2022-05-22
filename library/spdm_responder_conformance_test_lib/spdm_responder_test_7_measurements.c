/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_test.h"

#pragma pack(1)
typedef struct {
    uint8_t  version;
    uint32_t rsp_cap_flags;
    uint32_t hash_algo;
    uint32_t hash_size;
    uint32_t asym_algo;
    uint32_t signature_size;
    uint8_t slot_mask;
    uint8_t slot_count;
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];
} spdm_measurements_test_buffer_t;
#pragma pack()

bool spdm_test_case_measurements_setup_vca_digest (void *test_context,
    spdm_version_number_t spdm_version)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    uint32_t data32;
    uint16_t data16;
    uint8_t data8;
    spdm_measurements_test_buffer_t *test_buffer;
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    if (spdm_version != 0) {
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                        &spdm_version, sizeof(spdm_version));
    }

    data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    data8 = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
                                                 SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305 |
                                                 SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519 |
                                                 SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    status = libspdm_init_connection (spdm_context, false);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >= sizeof(spdm_measurements_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_measurements_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_measurements_test_buffer_t);

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version, &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &test_buffer->rsp_cap_flags, &data_size);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) ||
        (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) &&
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0))) {
        return false;
    }

    data_size = sizeof(test_buffer->hash_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &test_buffer->hash_algo, &data_size);
    test_buffer->hash_size = libspdm_get_hash_size(test_buffer->hash_algo);

    data_size = sizeof(test_buffer->asym_algo);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &test_buffer->asym_algo, &data_size);
    test_buffer->signature_size = libspdm_get_asym_signature_size(test_buffer->asym_algo);

    status = libspdm_get_digest (spdm_context, &test_buffer->slot_mask, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer->slot_count = 0;
    for (index = 0; index < SPDM_MAX_SLOT_COUNT; index++) {
        if ((test_buffer->slot_mask & (1 << index)) != 0) {
            test_buffer->slot_count ++;
        }
    }

    status = libspdm_get_certificate (spdm_context, 0, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    status = libspdm_challenge (spdm_context, 0, SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
                &test_buffer->measurement_summary_hash, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    spdm_test_context->test_scratch_buffer_size = offsetof(spdm_measurements_test_buffer_t, measurement_summary_hash) +
                                                  test_buffer->hash_size;

    return true;
}

bool spdm_test_case_measurements_setup_version_10 (void *test_context)
{
    return spdm_test_case_measurements_setup_vca_digest (test_context,
        SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_measurements_setup_version_any (void *test_context)
{
    return spdm_test_case_measurements_setup_vca_digest (test_context, 0);
}

bool spdm_test_case_measurements_setup_version_capabilities (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    spdm_version_number_t spdm_version;
    spdm_measurements_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    status = libspdm_get_version (spdm_context, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    status = libspdm_get_capabilities (spdm_context);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(sizeof(spdm_test_context->test_scratch_buffer) >= sizeof(spdm_measurements_test_buffer_t));
    libspdm_zero_mem(test_buffer, sizeof(spdm_measurements_test_buffer_t));
    spdm_test_context->test_scratch_buffer_size = sizeof(spdm_measurements_test_buffer_t);

    data_size = sizeof(test_buffer->rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &test_buffer->rsp_cap_flags, &data_size);
    if (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) ||
        (((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) &&
         ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0))) {
        return false;
    }

    spdm_version = 0;
    data_size = sizeof(spdm_version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &spdm_version, &data_size);
    test_buffer->version = (spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT);

    spdm_test_context->test_scratch_buffer_size = sizeof(test_buffer->version);

    return true;
}

bool spdm_test_measurement_parse_record (uint8_t number_of_blocks_in,
                                         uint32_t measurement_record_length_in,
                                         uint8_t *measurement_record,
                                         uint8_t *number_of_blocks_out,
                                         uint32_t *measurement_record_length_out)
{
    size_t index;
    uint16_t measurement_size;
    uint8_t *measurement_record_end;

    measurement_record_end = measurement_record + measurement_record_length_in;
    *number_of_blocks_out = 0;
    *measurement_record_length_out = 0;
    for (index = 0; index < number_of_blocks_in; index++) {
        if ((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) >
            (size_t)measurement_record_end) {
            return false;
        }
        measurement_size = ((spdm_measurement_block_common_header_t *)measurement_record)->measurement_size;
        if ((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) + measurement_size >
            (size_t)measurement_record_end) {
            return false;
        }
        *number_of_blocks_out += 1;
        *measurement_record_length_out += sizeof(spdm_measurement_block_common_header_t) + measurement_size;

        measurement_record = (void *)((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) + measurement_size);
    }

    LIBSPDM_ASSERT (*measurement_record_length_out <= measurement_record_length_in);
    if (*measurement_record_length_out < measurement_record_length_in) {
        return false;
    }

    return true;
}

bool spdm_test_measurement_calc_summary_hash (uint8_t spdm_version,
                                              uint32_t hash_algo,
                                              uint8_t number_of_blocks_in,
                                              uint32_t measurement_record_length_in,
                                              uint8_t *measurement_record,
                                              uint8_t *measurement_summary_hash)
{
    uint8_t measurement_data[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    uint32_t measurment_data_size;
    size_t index;
    uint16_t measurement_size;
    uint8_t *measurement_record_end;
    bool result;

    measurement_record_end = measurement_record + measurement_record_length_in;

    LIBSPDM_ASSERT (measurement_record_length_in <= LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);

    if (spdm_version < SPDM_MESSAGE_VERSION_12) {
        measurment_data_size = 0;
        for (index = 0; index < number_of_blocks_in; index++) {
            LIBSPDM_ASSERT ((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) <
                (size_t)measurement_record_end);
            measurement_size = ((spdm_measurement_block_common_header_t *)measurement_record)->measurement_size;
            LIBSPDM_ASSERT ((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) + measurement_size <=
                (size_t)measurement_record_end);

            LIBSPDM_ASSERT (measurment_data_size < LIBSPDM_MAX_MESSAGE_BUFFER_SIZE);
            libspdm_copy_mem (&measurement_data[measurment_data_size],
                              LIBSPDM_MAX_MESSAGE_BUFFER_SIZE - measurment_data_size,
                              measurement_record + sizeof(spdm_measurement_block_common_header_t),
                              measurement_size);

            measurment_data_size += measurement_size;
            measurement_record = (void *)((size_t)measurement_record + sizeof(spdm_measurement_block_common_header_t) + measurement_size);
        }
        result = libspdm_hash_all(hash_algo, measurement_data,
                              measurment_data_size, measurement_summary_hash);
    } else {
        result = libspdm_hash_all(hash_algo, measurement_record,
                              measurement_record_length_in, measurement_summary_hash);
    }
    return result;
}

void spdm_test_case_measurements_success_10 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_measurements_request_t spdm_request;
    size_t spdm_request_size;
    spdm_measurements_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_measurements_test_buffer_t *test_buffer;
    uint32_t measurement_record_length;
    uint16_t *opaque_length_ptr;
    uint32_t signature_size;
    uint8_t *signature_ptr;
    uint8_t slot_id;
    bool result;
    uint8_t number_of_blocks_out;
    uint32_t measurement_record_length_out;
    uint8_t measurement_summary_hash[LIBSPDM_MAX_HASH_SIZE];

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_measurements_test_buffer_t, measurement_summary_hash) +
                   test_buffer->hash_size);

    for (slot_id = 0; slot_id < 1; slot_id++) {
        if ((test_buffer->slot_mask & (0x1 << slot_id)) == 0) {
            continue ;
        }
        common_test_record_test_message ("test slot - 0x%02x\n", slot_id);

        /* get number */
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = test_buffer->version;
        spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {
            spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            spdm_request.header.param1 = 0;
        }
        spdm_request.header.param2 = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
        /* ignore spdm_request.nonce */
        spdm_request_size = offsetof(spdm_get_measurements_request_t, slot_id_param);

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                            &spdm_request, spdm_request_size,
                                            spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            return ;
        }

        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {
            signature_size = test_buffer->signature_size;
        } else {
            signature_size = 0;
        }
        if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                      SPDM_NONCE_SIZE + sizeof(uint16_t) +
                                      signature_size) {
            test_result = COMMON_TEST_RESULT_FAIL;
        } else {
            measurement_record_length = libspdm_read_uint24 (spdm_response->measurement_record_length);
            if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + signature_size) {
                test_result = COMMON_TEST_RESULT_FAIL;
            } else {
                opaque_length_ptr = (void *)((size_t)spdm_response + sizeof(spdm_measurements_response_t) +
                                      measurement_record_length + SPDM_NONCE_SIZE);
                if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + *opaque_length_ptr +
                                        signature_size) {
                    test_result = COMMON_TEST_RESULT_FAIL;
                } else {
                    test_result = COMMON_TEST_RESULT_PASS;
                }
            }
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }
        signature_ptr = (void *)((size_t)spdm_response + sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + *opaque_length_ptr);

        if (spdm_response->header.request_response_code == SPDM_MEASUREMENTS) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if (spdm_response->header.param1 > 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if (spdm_response->number_of_blocks == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 5,
            test_result, "response number_of_blocks - 0x%02x", spdm_response->number_of_blocks);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if (measurement_record_length == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 6,
            test_result, "response measurement_record_length - 0x%06x", measurement_record_length);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {

            status = libspdm_append_message_m(spdm_context, NULL,
                        &spdm_request, spdm_request_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_m failure");
                return ;
            }
            status = libspdm_append_message_m(spdm_context, NULL,
                        spdm_response, (size_t)signature_ptr - (size_t)spdm_response);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_m failure");
                return ;
            }

            result = libspdm_verify_measurement_signature(
                spdm_context, NULL, signature_ptr, signature_size);
            if (result) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 7,
                test_result, "response signature");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return ;
            }

            libspdm_reset_message_m (spdm_context, NULL);
        }


        /* get all */
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = test_buffer->version;
        spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {
            spdm_request.header.param1 = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        } else {
            spdm_request.header.param1 = 0;
        }
        spdm_request.header.param2 = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
        /* ignore spdm_request.nonce */
        spdm_request_size = offsetof(spdm_get_measurements_request_t, slot_id_param);

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                            &spdm_request, spdm_request_size,
                                            spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            return ;
        }

        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {
            signature_size = test_buffer->signature_size;
        } else {
            signature_size = 0;
        }
        if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                      SPDM_NONCE_SIZE + sizeof(uint16_t) +
                                      signature_size) {
            test_result = COMMON_TEST_RESULT_FAIL;
        } else {
            measurement_record_length = libspdm_read_uint24 (spdm_response->measurement_record_length);
            if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + signature_size) {
                test_result = COMMON_TEST_RESULT_FAIL;
            } else {
                opaque_length_ptr = (void *)((size_t)spdm_response + sizeof(spdm_measurements_response_t) +
                                      measurement_record_length + SPDM_NONCE_SIZE);
                if (spdm_response_size < sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + *opaque_length_ptr +
                                        signature_size) {
                    test_result = COMMON_TEST_RESULT_FAIL;
                } else {
                    test_result = COMMON_TEST_RESULT_PASS;
                }
            }
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 8,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }
        signature_ptr = (void *)((size_t)spdm_response + sizeof(spdm_measurements_response_t) +
                                        measurement_record_length + SPDM_NONCE_SIZE +
                                        sizeof(uint16_t) + *opaque_length_ptr);

        if (spdm_response->header.request_response_code == SPDM_MEASUREMENTS) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 9,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 10,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        spdm_test_measurement_parse_record (spdm_response->number_of_blocks,
                                            measurement_record_length,
                                            (void *)(spdm_response + 1),
                                            &number_of_blocks_out,
                                            &measurement_record_length_out);
        if ((spdm_response->number_of_blocks > 0) &&
            (spdm_response->number_of_blocks == number_of_blocks_out)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 11,
            test_result, "response number_of_blocks - 0x%02x, get - 0x%02x", spdm_response->number_of_blocks, number_of_blocks_out);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if ((measurement_record_length > 0) &&
            (measurement_record_length == measurement_record_length_out)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 12,
            test_result, "response measurement_record_length - 0x%06x, get - 0x%06x", measurement_record_length, measurement_record_length_out);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        result = spdm_test_measurement_calc_summary_hash (test_buffer->version,
                                                          test_buffer->hash_algo,
                                                          spdm_response->number_of_blocks,
                                                          measurement_record_length,
                                                          (void *)(spdm_response + 1),
                                                          measurement_summary_hash);
        if (!result) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "calc_summary_hash failure");
            return ;
        }
        if (libspdm_const_compare_mem (measurement_summary_hash,
                                       test_buffer->measurement_summary_hash,
                                       test_buffer->hash_size) == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 13,
            test_result, "response measurement summary hash");
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            return ;
        }

        if ((test_buffer->rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0) {

            status = libspdm_append_message_m(spdm_context, NULL,
                        &spdm_request, spdm_request_size);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_m failure");
                return ;
            }
            status = libspdm_append_message_m(spdm_context, NULL,
                        spdm_response, (size_t)signature_ptr - (size_t)spdm_response);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {
                common_test_record_test_assertion (
                    SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ID_END,
                    COMMON_TEST_RESULT_NOT_TESTED, "append_message_m failure");
                return ;
            }

            result = libspdm_verify_measurement_signature(
                spdm_context, NULL, signature_ptr, signature_size);
            if (result) {
                test_result = COMMON_TEST_RESULT_PASS;
            } else {
                test_result = COMMON_TEST_RESULT_FAIL;
            }
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, 14,
                test_result, "response signature");
            if (test_result == COMMON_TEST_RESULT_FAIL) {
                return ;
            }

            libspdm_reset_message_m (spdm_context, NULL);
        }
    }
}

void spdm_test_case_measurements_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_measurements_request_t spdm_request;
    size_t spdm_request_size;
    spdm_measurements_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_measurements_test_buffer_t *test_buffer;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_measurements_test_buffer_t, measurement_summary_hash) +
                   test_buffer->hash_size);

    mismatched_version[0] = (uint8_t)(test_buffer->version - 1);
    mismatched_version[1] = (uint8_t)(test_buffer->version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n", mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
        spdm_request.slot_id_param = 0;
        if (test_buffer->version == SPDM_MESSAGE_VERSION_10) {
            spdm_request_size = offsetof(spdm_get_measurements_request_t, slot_id_param);
        } else {
            spdm_request_size = sizeof(spdm_get_measurements_request_t);
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue ;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.param1 == SPDM_ERROR_CODE_VERSION_MISMATCH) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

void spdm_test_case_measurements_unexpected_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_measurements_request_t spdm_request;
    size_t spdm_request_size;
    spdm_measurements_response_t *spdm_response;
    size_t spdm_response_size;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    common_test_result_t test_result;
    spdm_measurements_test_buffer_t *test_buffer;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   sizeof(test_buffer->version));

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
    spdm_request.slot_id_param = 0;
    if (test_buffer->version == SPDM_MESSAGE_VERSION_10) {
        spdm_request_size = offsetof(spdm_get_measurements_request_t, slot_id_param);
    } else {
        spdm_request_size = sizeof(spdm_get_measurements_request_t);
    }

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return ;
    }

    if (spdm_response_size >= sizeof(spdm_error_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.request_response_code == SPDM_ERROR) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.spdm_version == test_buffer->version) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_UNEXPECTED_REQUEST) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, 4,
        test_result, "response param1 - 0x%02x", spdm_response->header.param1);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.param2 == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, 5,
        test_result, "response param2 - 0x%02x", spdm_response->header.param2);
}

void spdm_test_case_measurements_invalid_request (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_measurements_request_t spdm_request;
    spdm_get_measurements_request_t spdm_request_new;
    size_t spdm_request_size;
    spdm_measurements_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_measurements_test_buffer_t *test_buffer;
    size_t index;
    uint8_t slot_id;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    test_buffer = (void *)spdm_test_context->test_scratch_buffer;
    LIBSPDM_ASSERT(spdm_test_context->test_scratch_buffer_size ==
                   offsetof(spdm_measurements_test_buffer_t, measurement_summary_hash) +
                   test_buffer->hash_size);

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = test_buffer->version;
    spdm_request.header.request_response_code = SPDM_GET_MEASUREMENTS;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
    spdm_request.slot_id_param = 0;
    if (test_buffer->version == SPDM_MESSAGE_VERSION_10) {
        spdm_request_size = offsetof(spdm_get_measurements_request_t, slot_id_param);
    } else {
        spdm_request_size = sizeof(spdm_get_measurements_request_t);
    }

    for (index = 0; index < SPDM_MAX_SLOT_COUNT * 2; index++) {
        libspdm_copy_mem (&spdm_request_new, sizeof(spdm_request_new), &spdm_request, sizeof(spdm_request));

        if (index < SPDM_MAX_SLOT_COUNT * 2) {
            slot_id = (uint8_t)index;
            if ((slot_id < SPDM_MAX_SLOT_COUNT) &&
                ((test_buffer->slot_mask & (0x1 << slot_id)) != 0)) {
                continue ;
            }
            common_test_record_test_message ("test invalid slot - 0x%02x\n", slot_id);
            spdm_request_new.slot_id_param = slot_id;
        } else {
            break;
        }

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request_new, spdm_request_size,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue ;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, 1,
            test_result, "response size - %d", spdm_response_size);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.request_response_code == SPDM_ERROR) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.spdm_version == test_buffer->version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, 3,
            test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.param1 == SPDM_ERROR_CODE_INVALID_REQUEST) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS, SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_measurements[] = {
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, "spdm_test_case_measurements_success_10", spdm_test_case_measurements_success_10, spdm_test_case_measurements_setup_version_10},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, "spdm_test_case_measurements_version_mismatch", spdm_test_case_measurements_version_mismatch, spdm_test_case_measurements_setup_version_any},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, "spdm_test_case_measurements_unexpected_request", spdm_test_case_measurements_unexpected_request, spdm_test_case_measurements_setup_version_capabilities},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, "spdm_test_case_measurements_invalid_request", spdm_test_case_measurements_invalid_request, spdm_test_case_measurements_setup_version_any},
//  {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_11, "spdm_test_case_measurements_success_11", spdm_test_case_measurements_success_11, spdm_test_case_measurements_setup_version_11},
//  {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_12, "spdm_test_case_measurements_success_12", spdm_test_case_measurements_success_12, spdm_test_case_measurements_setup_version_12},
    {COMMON_TEST_ID_END, NULL, NULL},
};
