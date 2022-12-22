/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

/*
 * return one bit in the data according to the mask
 *
 * @retval 0                if (data & mask) is 0.
 * @retval 0xFFFFFFFF       if (data & mask) includes more than one bit.
 * @return (data & mask)    if (data & mask) includes one bit.
 */
uint32_t spdm_test_get_one_bit (uint32_t data, uint32_t mask)
{
    uint32_t final;
    uint8_t index;

    data = data & mask;

    final = 0;
    for (index = 0; index < 32; index++) {
        if ((data & (1 << index)) != 0) {
            if (final == 0) {
                /* first bit, record it to final */
                final = (1 << index);
            } else {
                /* more than one bit */
                return 0xFFFFFFFF;
            }
        }
    }
    return final;
}

/**
 * Initialize an SPDM context for SPDM-Responder-Validator, as well as secured message contexts.
 * The secured message contexts are appended to the context structure.
 *
 * The total size in bytes of the spdm_context and all secured message
 * contexts can be returned by libspdm_get_context_size().
 *
 * @param  spdm_context         A pointer to the SPDM context.
 *
 * @retval RETURN_SUCCESS       context is initialized.
 * @retval RETURN_DEVICE_ERROR  context initialization failed.
 */
libspdm_return_t libspdm_init_context_for_responder_validator(void *context)
{
    libspdm_context_t *spdm_context;
    void *secured_context;
    void *secured_contexts[LIBSPDM_MAX_SESSION_COUNT];
    size_t secured_context_size;
    size_t index;

    LIBSPDM_ASSERT(context != NULL);

    /* libspdm_get_context_size() allocates space for all secured message
     * contexts. They are appended to the general SPDM context. */
    spdm_context = context;
    secured_context = (void *)((size_t)(spdm_context + 1));
    secured_context_size = libspdm_secured_message_get_context_size();

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++)
    {
        secured_contexts[index] =
            (uint8_t *)secured_context + secured_context_size * index;
    }

    /* the different code between libspdm_init_context_for_responder_validator and libspdm_init_context
     * the libspdm_init_context is libspdm_zero_mem(spdm_context, sizeof(libspdm_context_t));
     * After libspdm_init_context_for_responder_validator, device don't need to register_device functon again.
     **/
    libspdm_zero_mem(&(spdm_context->version), sizeof(spdm_context->version));
    libspdm_zero_mem(&(spdm_context->transcript), sizeof(spdm_context->transcript));
    libspdm_zero_mem(&(spdm_context->spdm_session_state_callback),
                     sizeof(spdm_context->spdm_session_state_callback));
    libspdm_zero_mem(&(spdm_context->spdm_key_update_callback),
                     sizeof(spdm_context->spdm_key_update_callback));
    libspdm_zero_mem(&(spdm_context->spdm_connection_state_callback),
                     sizeof(spdm_context->spdm_connection_state_callback));
    libspdm_zero_mem(&(spdm_context->session_info), sizeof(spdm_context->session_info));
    libspdm_zero_mem(&(spdm_context->sender_buffer_size),
                     sizeof(spdm_context->sender_buffer_size));
    libspdm_zero_mem(&(spdm_context->sender_buffer), sizeof(spdm_context->sender_buffer));
    libspdm_zero_mem(&(spdm_context->retry_times), sizeof(spdm_context->retry_times));
    libspdm_zero_mem(&(spdm_context->response_state), sizeof(spdm_context->response_state));
    libspdm_zero_mem(&(spdm_context->receiver_buffer_size),
                     sizeof(spdm_context->receiver_buffer_size));
    libspdm_zero_mem(&(spdm_context->receiver_buffer), sizeof(spdm_context->receiver_buffer));
    libspdm_zero_mem(&(spdm_context->msg_log), sizeof(spdm_context->msg_log));
    libspdm_zero_mem(&(spdm_context->local_context), sizeof(spdm_context->local_context));
    libspdm_zero_mem(&(spdm_context->latest_session_id), sizeof(spdm_context->latest_session_id));
    libspdm_zero_mem(&(spdm_context->last_spdm_request_size),
                     sizeof(spdm_context->last_spdm_request_size));
    libspdm_zero_mem(&(spdm_context->last_spdm_request_session_id_valid),
                     sizeof(spdm_context->last_spdm_request_session_id_valid));
    libspdm_zero_mem(&(spdm_context->last_spdm_request_session_id),
                     sizeof(spdm_context->last_spdm_request_session_id));
    libspdm_zero_mem(&(spdm_context->last_spdm_request), sizeof(spdm_context->last_spdm_request));
    libspdm_zero_mem(&(spdm_context->last_spdm_error), sizeof(spdm_context->last_spdm_error));
    libspdm_zero_mem(&(spdm_context->handle_error_return_policy),
                     sizeof(spdm_context->handle_error_return_policy));
    libspdm_zero_mem(&(spdm_context->get_response_func),
                     sizeof(spdm_context->get_response_func));
    libspdm_zero_mem(&(spdm_context->get_encap_response_func),
                     sizeof(spdm_context->get_encap_response_func));
    libspdm_zero_mem(&(spdm_context->error_data), sizeof(spdm_context->error_data));
    libspdm_zero_mem(&(spdm_context->encap_context), sizeof(spdm_context->encap_context));
    libspdm_zero_mem(&(spdm_context->current_token), sizeof(spdm_context->current_token));
    libspdm_zero_mem(&(spdm_context->crypto_request), sizeof(spdm_context->crypto_request));
    libspdm_zero_mem(&(spdm_context->connection_info), sizeof(spdm_context->connection_info));
#if LIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP || LIBSPDM_ENABLE_CHUNK_CAP
    libspdm_zero_mem(&(spdm_context->chunk_context), sizeof(spdm_context->chunk_context));
#endif
    libspdm_zero_mem(&(spdm_context->cache_spdm_request_size),
                     sizeof(spdm_context->cache_spdm_request_size));
    libspdm_zero_mem(&(spdm_context->cache_spdm_request), sizeof(spdm_context->cache_spdm_request));
    libspdm_zero_mem(&(spdm_context->app_context_data_ptr),
                     sizeof(spdm_context->app_context_data_ptr));

    spdm_context->version = libspdm_context_struct_version;
    spdm_context->transcript.message_a.max_buffer_size =
        sizeof(spdm_context->transcript.message_a.buffer);
#if LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
    spdm_context->transcript.message_b.max_buffer_size =
        sizeof(spdm_context->transcript.message_b.buffer);
    spdm_context->transcript.message_c.max_buffer_size =
        sizeof(spdm_context->transcript.message_c.buffer);
    spdm_context->transcript.message_mut_b.max_buffer_size =
        sizeof(spdm_context->transcript.message_mut_b.buffer);
    spdm_context->transcript.message_mut_c.max_buffer_size =
        sizeof(spdm_context->transcript.message_mut_c.buffer);
    spdm_context->transcript.message_m.max_buffer_size =
        sizeof(spdm_context->transcript.message_m.buffer);
#endif
    spdm_context->retry_times = LIBSPDM_MAX_REQUEST_RETRY_TIMES;
    spdm_context->response_state = LIBSPDM_RESPONSE_STATE_NORMAL;
    spdm_context->current_token = 0;
    spdm_context->local_context.version.spdm_version_count = 3;
    spdm_context->local_context.version.spdm_version[0] = SPDM_MESSAGE_VERSION_10 <<
                                                          SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[1] = SPDM_MESSAGE_VERSION_11 <<
                                                          SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.version.spdm_version[2] = SPDM_MESSAGE_VERSION_12 <<
                                                          SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.secured_message_version.spdm_version_count = 1;
    spdm_context->local_context.secured_message_version.spdm_version[0] =
        SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    spdm_context->local_context.capability.st1 = SPDM_ST1_VALUE_US;

    spdm_context->encap_context.certificate_chain_buffer.max_buffer_size =
        sizeof(spdm_context->encap_context.certificate_chain_buffer.buffer);

    /* From the config.h, need different value for CHUNK - TBD*/
    spdm_context->local_context.capability.data_transfer_size = LIBSPDM_DATA_TRANSFER_SIZE;
    spdm_context->local_context.capability.max_spdm_msg_size = LIBSPDM_MAX_SPDM_MSG_SIZE;

    for (index = 0; index < LIBSPDM_MAX_SESSION_COUNT; index++) {
        if (secured_contexts[index] == NULL) {
            return LIBSPDM_STATUS_INVALID_PARAMETER;
        }

        spdm_context->session_info[index].secured_message_context = secured_contexts[index];
        libspdm_secured_message_init_context(
            spdm_context->session_info[index]
            .secured_message_context);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

/**
 * Free the memory of contexts within the SPDM context.
 * These are typically contexts whose memory has been allocated by the cryptography library.
 * This function does not free the SPDM context itself.
 *
 * @param[in]  spdm_context         A pointer to the SPDM context.
 *
 */
void libspdm_deinit_context_for_responder_validator(void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    void *spdm_context;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    libspdm_deinit_context(spdm_context);
}
