/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_test.h"

#pragma pack(1)
typedef struct {
    spdm_message_header_t header;
    uint16_t length;
    uint8_t measurement_specification;
    uint8_t other_params_support;
    uint32_t base_asym_algo;
    uint32_t base_hash_algo;
    uint8_t reserved2[12];
    uint8_t ext_asym_count;
    uint8_t ext_hash_count;
    uint16_t reserved3;
    spdm_negotiate_algorithms_common_struct_table_t struct_table[4];
} spdm_negotiate_algorithms_request_mine_t;

#pragma pack()

bool spdm_test_case_algorithms_setup_version_capabilities (void *test_context,
    spdm_version_number_t spdm_version)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    libspdm_data_parameter_t parameter;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version, sizeof(spdm_version));

    status = libspdm_get_version (spdm_context, NULL, NULL);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    status = libspdm_get_capabilities (spdm_context);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    return true;
}

bool spdm_test_case_algorithms_setup_version_10 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
        SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_algorithms_setup_version_11 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_algorithms_setup_version_12 (void *test_context)
{
    return spdm_test_case_algorithms_setup_version_capabilities (test_context,
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

void spdm_test_case_algorithms_success_10 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    uint32_t algo;
    common_test_result_t test_result;
    libspdm_data_parameter_t parameter;
    uint32_t rsp_cap_flags;
    size_t data_size;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
    spdm_request.header.param1 = 0;
    spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
    spdm_request.header.param2 = 0;
    spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    spdm_request.ext_asym_count = 0;
    spdm_request.ext_hash_count = 0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request.length,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return ;
    }

    if (spdm_response_size >= sizeof(spdm_algorithms_response_t)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.request_response_code == SPDM_ALGORITHMS) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 2,
        test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if ((spdm_response->length <= spdm_response_size) &&
        (spdm_response->length != sizeof(spdm_negotiate_algorithms_request_t) + 
                                 spdm_response->ext_asym_sel_count * sizeof(spdm_extended_algorithm_t) +
                                 spdm_response->ext_hash_sel_count * sizeof(spdm_extended_algorithm_t))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 4,
        test_result, "response length - 0x%04x", spdm_response->length);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->ext_asym_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 5,
        test_result, "response ext_asym_sel_count - 0x%02x", spdm_response->ext_asym_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->ext_hash_sel_count == 0) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 6,
        test_result, "response ext_hash_sel_count - 0x%02x", spdm_response->ext_hash_sel_count);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    rsp_cap_flags = 0;
    data_size = sizeof(rsp_cap_flags);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &rsp_cap_flags, &data_size);

    algo = spdm_test_get_one_bit (spdm_response->measurement_specification_sel,
                                    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
    if (algo != 0xFFFFFFFF) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 7,
        test_result, "response measurement_specification_sel - 0x%02x", spdm_response->measurement_specification_sel);

    algo = spdm_test_get_one_bit (spdm_response->measurement_hash_algo,
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256 |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384 |
                                    SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512);
    if (((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) != 0) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if (((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) &&
               (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 8,
        test_result, "response measurement_hash_algo - 0x%08x", spdm_response->measurement_hash_algo);

    algo = spdm_test_get_one_bit (spdm_response->base_asym_sel,
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521);
    if ((((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0) &&
               ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) == 0)) &&
              (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 9,
        test_result, "response base_asym_sel - 0x%08x", spdm_response->base_asym_sel);

    algo = spdm_test_get_one_bit (spdm_response->base_hash_sel,
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512);
    if ((((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) != 0) ||
         ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) != 0)) &&
        ((algo != 0xFFFFFFFF) && (algo != 0x0))) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else if ((((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0) &&
               ((rsp_cap_flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) == 0)) &&
              (algo == 0x0)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, 10,
        test_result, "response base_hash_sel - 0x%08x", spdm_response->base_hash_sel);
}

void spdm_test_case_algorithms_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_negotiate_algorithms_request_mine_t spdm_request;
    spdm_algorithms_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    spdm_version_number_t version;
    libspdm_data_parameter_t parameter;
    size_t data_size;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    version = 0;
    data_size = sizeof(version);
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter, &version, &data_size);
    version = (version >> SPDM_VERSION_NUMBER_SHIFT_BIT);
    mismatched_version[0] = (uint8_t)(version - 1);
    mismatched_version[1] = (uint8_t)(version + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n", mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request.length = sizeof(spdm_request) - sizeof(spdm_request.struct_table);
        spdm_request.header.param1 = 0;
        spdm_request.header.request_response_code = SPDM_NEGOTIATE_ALGORITHMS;
        spdm_request.header.param2 = 0;
        spdm_request.measurement_specification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
        spdm_request.base_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                                    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
        spdm_request.base_hash_algo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384 |
                                    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
        spdm_request.ext_asym_count = 0;
        spdm_request.ext_hash_count = 0;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                           &spdm_request, spdm_request.length,
                                           spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue ;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.spdm_version == version) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_ALGORITHMS, SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_algorithms[] = {
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, "spdm_test_case_algorithms_success_10", spdm_test_case_algorithms_success_10, spdm_test_case_algorithms_setup_version_10},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, "spdm_test_case_algorithms_version_mismatch", spdm_test_case_algorithms_version_mismatch, spdm_test_case_algorithms_setup_version_11},
    {COMMON_TEST_ID_END, NULL, NULL},
};
