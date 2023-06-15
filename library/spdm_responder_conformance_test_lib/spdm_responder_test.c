/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder_test.h"

common_test_group_t m_spdm_test_groups[] = {
    {SPDM_RESPONDER_TEST_GROUP_VERSION,           "spdm_test_group_version",
     m_spdm_test_group_version},
    {SPDM_RESPONDER_TEST_GROUP_CAPABILITIES,      "spdm_test_group_capabilities",
     m_spdm_test_group_capabilities},
    {SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,        "spdm_test_group_algorithms",
     m_spdm_test_group_algorithms},
    {SPDM_RESPONDER_TEST_GROUP_DIGESTS,           "spdm_test_group_digests",
     m_spdm_test_group_digests},
    {SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,       "spdm_test_group_certificate",
     m_spdm_test_group_certificate},
    {SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,    "spdm_test_group_challenge_auth",
     m_spdm_test_group_challenge_auth},
    {SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS,      "spdm_test_group_measurements",
     m_spdm_test_group_measurements},
    {SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,  "spdm_test_group_key_exchange_rsp",
     m_spdm_test_group_key_exchange_rsp},
    {SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,        "spdm_test_group_finish_rsp",
     m_spdm_test_group_finish_rsp},
    {SPDM_RESPONDER_TEST_GROUP_HEARTBEAT_ACK,     "spdm_test_group_heartbeat_ack",
     m_spdm_test_group_heartbeat_ack},
    {SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,    "spdm_test_group_key_update_ack",
     m_spdm_test_group_key_update_ack},
    {SPDM_RESPONDER_TEST_GROUP_END_SESSION_ACK,   "spdm_test_group_end_session_ack",
     m_spdm_test_group_end_session_ack},
    {COMMON_TEST_ID_END, NULL, NULL},
};

common_test_suite_t m_spdm_test_suite = {
    "spdm_responder_conformance_test",
    m_spdm_test_groups,
};

void spdm_responder_conformance_test (void *spdm_context,
                                      const common_test_suite_config_t *test_config)
{
    spdm_test_context_t spdm_test_context;

    libspdm_zero_mem(&spdm_test_context, sizeof(spdm_test_context_t));
    spdm_test_context.spdm_context = spdm_context;
    common_test_run_test_suite (&spdm_test_context, &m_spdm_test_suite, test_config);
}

void spdm_test_case_common_teardown (void *test_context)
{
    spdm_test_context_t *spdm_test_context;
    libspdm_context_t *spdm_context;
    libspdm_device_send_message_func send_message;
    libspdm_device_receive_message_func receive_message;
    libspdm_transport_encode_message_func transport_encode_message;
    libspdm_transport_decode_message_func transport_decode_message;
    libspdm_device_acquire_sender_buffer_func acquire_sender_buffer;
    libspdm_device_release_sender_buffer_func release_sender_buffer;
    libspdm_device_acquire_receiver_buffer_func acquire_receiver_buffer;
    libspdm_device_release_receiver_buffer_func release_receiver_buffer;
    uint32_t transport_header_size;
    uint32_t transport_tail_size;
    uint32_t max_spdm_msg_size;
    size_t sender_buffer_size;
    size_t receiver_buffer_size;
    void *scratch_buffer;
    size_t scratch_buffer_size;

    spdm_test_context = test_context;
    spdm_context = spdm_test_context->spdm_context;
    libspdm_deinit_context(spdm_context);

    /* the libspdm_init_context is libspdm_zero_mem(spdm_context, sizeof(libspdm_context_t));
     * We need to save and restore the registered functons and buffers.
     **/
    send_message = spdm_context->send_message;
    receive_message = spdm_context->receive_message;

    max_spdm_msg_size = spdm_context->local_context.capability.max_spdm_msg_size;
    transport_header_size = spdm_context->local_context.capability.transport_header_size;
    transport_tail_size = spdm_context->local_context.capability.transport_tail_size;
    transport_encode_message = spdm_context->transport_encode_message;
    transport_decode_message = spdm_context->transport_decode_message;

    sender_buffer_size = spdm_context->sender_buffer_size;
    receiver_buffer_size = spdm_context->receiver_buffer_size;
    acquire_sender_buffer = spdm_context->acquire_sender_buffer;
    release_sender_buffer = spdm_context->release_sender_buffer;
    acquire_receiver_buffer = spdm_context->acquire_receiver_buffer;
    release_receiver_buffer = spdm_context->release_receiver_buffer;

    scratch_buffer = spdm_context->scratch_buffer;
    scratch_buffer_size = spdm_context->scratch_buffer_size;

    libspdm_init_context (spdm_context);

    libspdm_register_device_io_func(spdm_context, send_message, receive_message);
    libspdm_register_transport_layer_func(spdm_context,
                                          max_spdm_msg_size,
                                          transport_header_size,
                                          transport_tail_size,
                                          transport_encode_message,
                                          transport_decode_message);
    libspdm_register_device_buffer_func(spdm_context,
                                        (uint32_t)sender_buffer_size,
                                        (uint32_t)receiver_buffer_size,
                                        acquire_sender_buffer,
                                        release_sender_buffer,
                                        acquire_receiver_buffer,
                                        release_receiver_buffer);
    libspdm_set_scratch_buffer (spdm_context, scratch_buffer, scratch_buffer_size);
}
