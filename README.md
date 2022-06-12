# SPDM Responder Validator

Copyright 2022 DMTF. All rights reserved.

## About

The SPDM Responder Validator tests the protocol behavior of an SPDM Responder device to validate that it conforms to the SPDM specification.

Reference:

   [DSP0274](https://www.dmtf.org/dsp/DSP0274)  Security Protocol and Data Model (SPDM) Specification (version [1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.1.pdf), version [1.1.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf) and version [1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.0.pdf))

   [DSP0277](https://www.dmtf.org/dsp/DSP0277)  Secured Messages using SPDM Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0.pdf))

## Test Design

The test case design is described below.

[1. Test for VERSION](doc/1.Version.md)

[2. Test for CAPABILITIES](doc/2.Capabilities.md)

[3. Test for ALGORITHMS](doc/3.Algorithms.md)

[4. Test for DIGESTS](doc/4.Digests.md)

[5. Test for CERTIFICATE](doc/5.Certificate.md)

[6. Test for CHALLENGE_AUTH](doc/6.ChallengeAuth.md)

[7. Test for MEASUREMENT](doc/7.Measurements.md)

[8. Test for KEY_EXCHANGE_RSP](doc/8.KeyExchangeRsp.md)

[9. Test for FINISH_RSP](doc/9.FinishRsp.md)

10. Test for PSK_EXCHANGE_RSP

11. Test for PSK_FINISH_RSP

[12. Test for HEARTBEAT_ACK](doc/12.HeartbeatAck.md)

[13. Test for KEY_UPDATE_ACK](doc/13.KeyUpdateAck.md)

14. Test for ENCAPSULATED_REQUEST

15. Test for ENCAPSULATED_RESPONSE_ACK

[16. Test for END_SESSION_ACK](doc/16.EndSessionAck.md)

17. Test for CSR

18. Test for SET_CERTIFICATE_RSP

19. Test for CHUNK_SEND_ACK

20. Test for CHUNK_RESPONSE

### Test Assumptions

The SPDM specification allows vendor-defined algorithms as an implementation choice. The conformance test only validates the SPDM-defined algorithms and it does not support the algorithm extensions including ExtAsym (1.0+), ExtHash (1.0+), AlgExternal (1.1+), and OpaqueDataFmt0 (1.2+). If a device does not support SPDM-defined algorithms and only supports the vendor-defined algorithms then there is no way to run the test.

The SPDM specification allows vendor-defined raw public key provisioning as an implementation choice. The conformance test only validates the SPDM-defined X.509 style public certificate chain and it does not support the vendor-defined raw public key. If a device does not support SPDM-defined X.509 style public certificate chains (CERT_CAP) and only supports the vendor-defined raw public key (PUB_KEY_ID_CAP in 1.1+) then there is no way to run the certificate related test.

The device is not in update mode during test.

Some tests rely on the basic SPDM infrastructure. For example, RESPOND_IF_READY is used for ERROR(ResponseNotReady) if the cryptography timeout occurs or chunking is used if the message is too long. Failure to support such SPDM infrastructure may cause the related test abort.

### Test Criteria

The test checks what is mandated in the SPDM specification.
If the test passes, there will be a PASS assertion. Otherwise, there will be a FAIL assertion.

Some features in SPDM specification are recommended or optional, but not mandated. Those features may or might not be tested.
If the test passes, there will be a PASS assertion. If the feature is not implemented, there will NOT be a FAIL assertion.

### Test Not Covered

The test for SPDM vendor-defined messages is not covered.

Some tests may require the Responder to provision the environment. For example, mutual authentication may require the Responder to provision the certificate from the Requester. Pre-shared Key (PSK) exchange requires the Requester and Responder to provision the PSK. CSR retrival requires the Requester to provide OEM-specific valid RequesterInfo. These tests are not covered.

Some SPDM flows (such as mutual authentication and Responder-initiated key update) are controlled and triggered by the Responder. These tests are not covered.

## Test Implementation

The test cases implementation is based upon DMTF's [libspdm](https://github.com/DMTF/libspdm). The test cases checkpoint has no assumption on the libspdm implementation.

The test case implemenmtation supports the following transport binding by default:

   MCTP and secured MCTP follow :

   [DSP0275](https://www.dmtf.org/dsp/DSP0275)  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   [DSP0276](https://www.dmtf.org/dsp/DSP0276)  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0.pdf))

   PCIE follows :

   PCI Express Base Specification Revision 6.0 (version [1.0](https://members.pcisig.com/wg/PCI-SIG/document/16609))

### Test Integration

   The test suite header file is [spdm_responder_conformance_test_lib.h](https://github.com/DMTF/SPDM-Responder-Validator/blob/master/include/library/spdm_responder_conformance_test_lib.h).

   The test integrator shall link the test suite - [spdm_responder_conformance_test_lib](https://github.com/DMTF/SPDM-Responder-Validator/tree/master/library/spdm_responder_conformance_test_lib) to the test application.

   The entrypoint is `spdm_responder_conformance_test()`.
   ```
   void spdm_responder_conformance_test (void *spdm_context,
                                         const common_test_suite_config_t *test_config);
   ```
   
   The test integrator shall preprare a `spdm_context` and initialize it with required functions callbacks.
   ```
void *spdm_test_client_init(void)
{
    void *spdm_context;
    size_t scratch_buffer_size;

    m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (m_spdm_context == NULL) {
        return NULL;
    }
    spdm_context = m_spdm_context;
    libspdm_init_context(spdm_context);
    scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(m_spdm_context);
    m_scratch_buffer = (void *)malloc(scratch_buffer_size);
    if (m_scratch_buffer == NULL) {
        free(m_spdm_context);
        m_spdm_context = NULL;
        return NULL;
    }

    libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                    spdm_device_receive_message);
    if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
        libspdm_register_transport_layer_func(
            spdm_context, libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message,
            libspdm_transport_mctp_get_header_size);
    } else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        libspdm_register_transport_layer_func(
            spdm_context, libspdm_transport_pci_doe_encode_message,
            libspdm_transport_pci_doe_decode_message,
            libspdm_transport_pci_doe_get_header_size);
    } else {
        return NULL;
    }
    libspdm_register_device_buffer_func(spdm_context,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, scratch_buffer_size);

    return m_spdm_context;
}
   ```

   The test integrator shall preprare a `test_config` and initialize it with required test cases.
   ```
common_test_case_config_t m_spdm_test_group_version_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_VERSION_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_VERSION_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_capabilities_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_11, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_12, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CAPABILITIES_UNEXPECTED_REQUEST_NON_IDENTICAL, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_algorithms_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_digests_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_DIGESTS_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_DIGESTS_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_DIGESTS_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_certificate_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SPDM_X509_CERTIFICATE, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_challenge_auth_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B1C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B2C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B3C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B1C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B2C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B3C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B4C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B1C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B2C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B3C1, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B4C1, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_measurements_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SPDM_MEASUREMENT_BLOCK, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_11, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_12, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_12_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_key_exchange_rsp_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11_HS_CLEAR, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12_HS_CLEAR, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_finish_rsp_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11_HS_CLEAR, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA_HS_CLEAR, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12_HS_CLEAR, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_heartbeat_ack_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_VERSION_MISMATCH_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_SESSION_REQUIRED, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_key_update_ack_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_case_config_t m_spdm_test_group_end_session_ack_configs[] = {
    {SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_SUCCESS_11_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_VERSION_MISMATCH_IN_DHE_SESSION, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS, COMMON_TEST_ACTION_RUN},
    {SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_SESSION_REQUIRED, COMMON_TEST_ACTION_RUN},
    {COMMON_TEST_ID_END, COMMON_TEST_ACTION_SKIP},
};

common_test_group_config_t m_spdm_test_group_configs[] = {
    {SPDM_RESPONDER_TEST_GROUP_VERSION,           COMMON_TEST_ACTION_RUN, m_spdm_test_group_version_configs},
    {SPDM_RESPONDER_TEST_GROUP_CAPABILITIES,      COMMON_TEST_ACTION_RUN, m_spdm_test_group_capabilities_configs},
    {SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,        COMMON_TEST_ACTION_RUN, m_spdm_test_group_algorithms_configs},
    {SPDM_RESPONDER_TEST_GROUP_DIGESTS,           COMMON_TEST_ACTION_RUN, m_spdm_test_group_digests_configs},
    {SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,       COMMON_TEST_ACTION_RUN, m_spdm_test_group_certificate_configs},
    {SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,    COMMON_TEST_ACTION_RUN, m_spdm_test_group_challenge_auth_configs},
    {SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS,      COMMON_TEST_ACTION_RUN, m_spdm_test_group_measurements_configs},
    {SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,  COMMON_TEST_ACTION_RUN, m_spdm_test_group_key_exchange_rsp_configs},
    {SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,        COMMON_TEST_ACTION_RUN, m_spdm_test_group_finish_rsp_configs},
    {SPDM_RESPONDER_TEST_GROUP_HEARTBEAT_ACK,     COMMON_TEST_ACTION_RUN, m_spdm_test_group_heartbeat_ack_configs},
    {SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,    COMMON_TEST_ACTION_RUN, m_spdm_test_group_key_update_ack_configs},
    {SPDM_RESPONDER_TEST_GROUP_END_SESSION_ACK,   COMMON_TEST_ACTION_RUN, m_spdm_test_group_end_session_ack_configs},
    {COMMON_TEST_ID_END,                          COMMON_TEST_ACTION_SKIP, NULL},
};

common_test_suite_config_t m_spdm_responder_validator_config = {
    "spdm_responder_validator default config",
    m_spdm_test_group_configs
};
   ```

## Run Test

### Run Test with [spdm_emu](https://github.com/DMTF/spdm-emu)

   The spdm_emu provides an example [spdm_responder_validator_emu](https://github.com/DMTF/spdm-emu/tree/main/spdm_emu/spdm_responder_validator_emu).

   A user can follow normal spdm_emu build process. The output binaries are at spdm_dump/build/bin. The user should run `spdm_responder_emu` to launch the device, then run `spdm_responder_validator_emu` to launch the test.

## Sample Output

```
test_suite_config (spdm_responder_validator default config)
test_suite (spdm_responder_conformance_test)
test group 1 (spdm_test_group_version) - start
  test case 1.1 (spdm_test_case_version_success) - start
    test assertion 1.1.1 - PASS response size - 12
    test assertion 1.1.2 - PASS response code - 0x04
    test assertion 1.1.3 - PASS response version - 0x10
    test assertion 1.1.4 - PASS response version_number_entry_count - 0x03
    test assertion 1.1.5 - PASS response version_number_entry - 0x1000
    test assertion 1.1.5 - PASS response version_number_entry - 0x1100
    test assertion 1.1.5 - PASS response version_number_entry - 0x1200
  test case 1.1 (spdm_test_case_version_success) - stop
  test case 1.2 (spdm_test_case_version_invalid_request) - start
    test assertion 1.2.1 - PASS response size - 4
    test assertion 1.2.2 - PASS response code - 0x7f
    test assertion 1.2.3 - PASS response version - 0x10
    test assertion 1.2.4 - PASS response param1 - 0x01
    test assertion 1.2.5 - PASS response param2 - 0x00
  test case 1.2 (spdm_test_case_version_invalid_request) - stop
test group 1 (spdm_test_group_version) - stop
test group 2 (spdm_test_group_capabilities) - start
  test case 2.1 (spdm_test_case_capabilities_success_10) - setup enter
  test case 2.1 (spdm_test_case_capabilities_success_10) - setup exit (1)
  test case 2.1 (spdm_test_case_capabilities_success_10) - start
    test assertion 2.1.1 - PASS response size - 12
    test assertion 2.1.2 - PASS response code - 0x61
    test assertion 2.1.3 - PASS response version - 0x10
    test assertion 2.1.4 - PASS response flags - 0x0000fbf7
  test case 2.1 (spdm_test_case_capabilities_success_10) - stop
  test case 2.2 (spdm_test_case_capabilities_version_mismatch) - setup enter
  test case 2.2 (spdm_test_case_capabilities_version_mismatch) - setup exit (1)
  test case 2.2 (spdm_test_case_capabilities_version_mismatch) - start
    test msg: test mismatched_version - 0xff
    test assertion 2.2.1 - PASS response size - 4
    test assertion 2.2.2 - PASS response code - 0x7f
    test assertion 2.2.3 - PASS response version - 0x10
    test assertion 2.2.4 - PASS response param1 - 0x41
    test assertion 2.2.5 - PASS response param2 - 0x00
    test msg: test mismatched_version - 0x01
    test assertion 2.2.1 - PASS response size - 4
    test assertion 2.2.2 - PASS response code - 0x7f
    test assertion 2.2.3 - PASS response version - 0x10
    test assertion 2.2.4 - PASS response param1 - 0x41
    test assertion 2.2.5 - PASS response param2 - 0x00
  test case 2.2 (spdm_test_case_capabilities_version_mismatch) - stop
test group 2 (spdm_test_group_capabilities) - stop
test group 3 (spdm_test_group_algorithms) - start
  test case 3.1 (spdm_test_case_algorithms_success_10) - setup enter
  test case 3.1 (spdm_test_case_algorithms_success_10) - setup exit (1)
  test case 3.1 (spdm_test_case_algorithms_success_10) - start
    test assertion 3.1.1 - PASS response size - 36
    test assertion 3.1.2 - PASS response code - 0x63
    test assertion 3.1.3 - PASS response version - 0x10
    test assertion 3.1.4 - PASS response length - 0x0024
    test assertion 3.1.5 - PASS response ext_asym_sel_count - 0x00
    test assertion 3.1.6 - PASS response ext_hash_sel_count - 0x00
    test assertion 3.1.7 - PASS response measurement_specification_sel - 0x01
    test assertion 3.1.8 - PASS response measurement_hash_algo - 0x00000008
    test assertion 3.1.9 - PASS response base_asym_sel - 0x00000080
    test assertion 3.1.10 - PASS response base_hash_sel - 0x00000002
  test case 3.1 (spdm_test_case_algorithms_success_10) - stop
  test case 3.2 (spdm_test_case_algorithms_version_mismatch) - setup enter
  test case 3.2 (spdm_test_case_algorithms_version_mismatch) - setup exit (1)
  test case 3.2 (spdm_test_case_algorithms_version_mismatch) - start
    test msg: test mismatched_version - 0x10
    test assertion 3.2.1 - PASS response size - 4
    test assertion 3.2.2 - PASS response code - 0x7f
    test assertion 3.2.3 - PASS response version - 0x11
    test assertion 3.2.4 - PASS response param1 - 0x41
    test assertion 3.2.5 - PASS response param2 - 0x00
    test msg: test mismatched_version - 0x12
    test assertion 3.2.1 - PASS response size - 4
    test assertion 3.2.2 - PASS response code - 0x7f
    test assertion 3.2.3 - PASS response version - 0x11
    test assertion 3.2.4 - PASS response param1 - 0x41
    test assertion 3.2.5 - PASS response param2 - 0x00
  test case 3.2 (spdm_test_case_algorithms_version_mismatch) - stop
test group 3 (spdm_test_group_algorithms) - stop

test suite (spdm_responder_conformance_test) - pass: 46, fail: 0
test group 1 (spdm_test_group_version) - pass: 12, fail: 0
  test case 1.1 (spdm_test_case_version_success) - pass: 7, fail: 0
  test case 1.2 (spdm_test_case_version_invalid_request) - pass: 5, fail: 0
test group 2 (spdm_test_group_capabilities) - pass: 14, fail: 0
  test case 2.1 (spdm_test_case_capabilities_success_10) - pass: 4, fail: 0
  test case 2.2 (spdm_test_case_capabilities_version_mismatch) - pass: 10, fail: 0
test group 3 (spdm_test_group_algorithms) - pass: 20, fail: 0
  test case 3.1 (spdm_test_case_algorithms_success_10) - pass: 10, fail: 0
  test case 3.2 (spdm_test_case_algorithms_version_mismatch) - pass: 10, fail: 0
test result done
```
