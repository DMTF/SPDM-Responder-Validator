/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
**/

#include "spdm_responder_test.h"

bool spdm_test_case_capabilities_setup_version (void *test_context,
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

    return true;
}

bool spdm_test_case_capabilities_setup_version_all (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    version_number_entry_count = LIBSPDM_MAX_VERSION_COUNT;
    status = libspdm_get_version (spdm_context, &version_number_entry_count, version_number_entry);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        return false;
    }

    libspdm_copy_mem (spdm_test_context->test_scratch_buffer,
                      sizeof(spdm_test_context->test_scratch_buffer),
                      &version_number_entry_count,
                      sizeof(version_number_entry_count));
    libspdm_copy_mem (spdm_test_context->test_scratch_buffer + sizeof(version_number_entry_count),
                      sizeof(spdm_test_context->test_scratch_buffer) - sizeof(version_number_entry_count),
                      version_number_entry,
                      sizeof(spdm_version_number_t) * version_number_entry_count);
    spdm_test_context->test_scratch_buffer_size = sizeof(version_number_entry_count) +
        sizeof(spdm_version_number_t) * version_number_entry_count;

    return true;
}

bool spdm_test_case_capabilities_setup_version_10 (void *test_context)
{
    return spdm_test_case_capabilities_setup_version (test_context,
        SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_capabilities_setup_version_11 (void *test_context)
{
    return spdm_test_case_capabilities_setup_version (test_context,
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

bool spdm_test_case_capabilities_setup_version_12 (void *test_context)
{
    return spdm_test_case_capabilities_setup_version (test_context,
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT);
}

void spdm_test_case_capabilities_success_10 (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_capabilities_request_t spdm_request;
    size_t spdm_request_size;
    spdm_capabilities_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    uint32_t flags;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
    spdm_request.header.spdm_version = SPDM_MESSAGE_VERSION_10;
    spdm_request_size = sizeof(spdm_request.header);
    spdm_request.header.request_response_code = SPDM_GET_CAPABILITIES;
    spdm_request.header.param1 = 0;
    spdm_request.header.param2 = 0;

    spdm_response = (void *)message;
    spdm_response_size = sizeof(message);
    libspdm_zero_mem(message, sizeof(message));
    status = libspdm_send_receive_data(spdm_context, NULL, false,
                                       &spdm_request, spdm_request_size,
                                       spdm_response, &spdm_response_size);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, COMMON_TEST_ID_END,
            COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
        return ;
    }

    if (spdm_response_size >= sizeof(spdm_capabilities_response_t) -
            sizeof(spdm_response->data_transfer_size) -
            sizeof(spdm_response->max_spdm_msg_size)) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, 1,
        test_result, "response size - %d", spdm_response_size);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    if (spdm_response->header.request_response_code == SPDM_CAPABILITIES) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, 2,
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
        SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, 3,
        test_result, "response version - 0x%02x", spdm_response->header.spdm_version);
    if (test_result == COMMON_TEST_RESULT_FAIL) {
        return ;
    }

    flags = spdm_response->flags;
    if ((flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) != SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) {
        test_result = COMMON_TEST_RESULT_PASS;
    } else {
        test_result = COMMON_TEST_RESULT_FAIL;
    }
    common_test_record_test_assertion (
        SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, 4,
        test_result, "response flags - 0x%08x", spdm_response->flags);
}

void spdm_test_case_capabilities_version_mismatch (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;
    libspdm_return_t status;
    spdm_get_capabilities_request_t spdm_request;
    size_t spdm_request_size;
    spdm_error_response_t *spdm_response;
    uint8_t message[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    size_t spdm_response_size;
    common_test_result_t test_result;
    uint8_t mismatched_version[] = {
        SPDM_MESSAGE_VERSION_10 - 1,
        SPDM_MESSAGE_VERSION_12 + 1,
    };
    size_t index;
    uint8_t version_number_entry_count;
    spdm_version_number_t version_number_entry[LIBSPDM_MAX_VERSION_COUNT];

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;

    libspdm_copy_mem (&version_number_entry_count,
                      sizeof(version_number_entry_count),
                      spdm_test_context->test_scratch_buffer,
                      sizeof(version_number_entry_count));
    libspdm_copy_mem (version_number_entry,
                      sizeof(version_number_entry),
                      spdm_test_context->test_scratch_buffer + sizeof(version_number_entry_count),
                      sizeof(spdm_version_number_t) * version_number_entry_count);

    mismatched_version[0] = (uint8_t)(version_number_entry[version_number_entry_count - 1] - 1);
    mismatched_version[1] = (uint8_t)(version_number_entry[0] + 1);

    for (index = 0; index < LIBSPDM_ARRAY_SIZE(mismatched_version); index++) {
        common_test_record_test_message ("test mismatched_version - 0x%02x\n", mismatched_version[index]);
        libspdm_zero_mem(&spdm_request, sizeof(spdm_request));
        spdm_request.header.spdm_version = mismatched_version[index];
        spdm_request_size = sizeof(spdm_request.header);
        spdm_request.header.request_response_code = SPDM_GET_CAPABILITIES;
        spdm_request.header.param1 = 0;
        spdm_request.header.param2 = 0;

        spdm_response = (void *)message;
        spdm_response_size = sizeof(message);
        libspdm_zero_mem(message, sizeof(message));
        status = libspdm_send_receive_data(spdm_context, NULL, false,
                                          &spdm_request, spdm_request_size,
                                          spdm_response, &spdm_response_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            common_test_record_test_assertion (
                SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, COMMON_TEST_ID_END,
                COMMON_TEST_RESULT_NOT_TESTED, "send/receive failure");
            continue ;
        }

        if (spdm_response_size >= sizeof(spdm_error_response_t)) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, 1,
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
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, 2,
            test_result, "response code - 0x%02x", spdm_response->header.request_response_code);
        if (test_result == COMMON_TEST_RESULT_FAIL) {
            continue ;
        }

        if (spdm_response->header.spdm_version == SPDM_MESSAGE_VERSION_10) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, 3,
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
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, 4,
            test_result, "response param1 - 0x%02x", spdm_response->header.param1);

        if (spdm_response->header.param2 == 0) {
            test_result = COMMON_TEST_RESULT_PASS;
        } else {
            test_result = COMMON_TEST_RESULT_FAIL;
        }
        common_test_record_test_assertion (
            SPDM_RESPONDER_TEST_GROUP_CAPABILITIES, SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, 5,
            test_result, "response param2 - 0x%02x", spdm_response->header.param2);
    }
}

common_test_case_t m_spdm_test_group_capabilities[] = {
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, "spdm_test_case_capabilities_success_10", spdm_test_case_capabilities_success_10, spdm_test_case_capabilities_setup_version_10},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, "spdm_test_case_capabilities_version_mismatch", spdm_test_case_capabilities_version_mismatch, spdm_test_case_capabilities_setup_version_all},
    {COMMON_TEST_ID_END, NULL, NULL},
};
