# SPDM Responder Validator

Copyright 2022 DMTF. All rights reserved.

## About

The SPDM Responder Validator tests the SPDM protocol behavior of a SPDM responder device to validate that it conforms to the SPDM specification.

Reference:

   [DSP0274](https://www.dmtf.org/dsp/DSP0274)  Security Protocol and Data Model (SPDM) Specification (version [1.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.1.pdf), version [1.1.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf) and version [1.2.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.0.pdf))

   [DSP0277](https://www.dmtf.org/dsp/DSP0277)  Secured Messages using SPDM Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0.pdf))

## Test Design

[1. Test for VERSION](doc/1.Version.md)

[2. Test for CAPABILITIES](doc/2.Capabilities.md)

[3. Test for ALGORITHMS](doc/3.Algorithms.md)

[4. Test for DIGESTS](doc/4.Digests.md)

[5. Test for CERTIFICATE](doc/5.Certificate.md)

[6. Test for CHALLENGE_AUTH](doc/6.ChallengeAuth.md)

[7. Test for MEASUREMENT](doc/7.Measurements.md)

[8. Test for KEY_EXCHANGE_RSP](doc/8.KeyExchangeRsp.md)

[9. Test for FINISH_RSP](doc/9.FinishRsp.md)

[10. Test for PSK_EXCHANGE_RSP](doc/10.PskExchangeRsp.md)

[11. Test for PSK_FINISH_RSP](doc/11.PskFinishRsp.md)

[12. Test for HEARTBEAT_ACK](doc/12.HeartbeatAck.md)

[13. Test for KEY_UPDATE_ACK](doc/13.KeyUpdateAck.md)

[14. Test for ENCAPSULATED_REQUEST](doc/14.EncapsulatedRequest.md)

[15. Test for ENCAPSULATED_RESPONSE_ACK](doc/15.EncapsulatedResponseAck.md)

[16. Test for END_SESSION_ACK](doc/16.EndSessionAck.md)

[17. Test for CSR](doc/17.Csr.md)

[18. Test for SET_CERTIFICATE_RSP](doc/18.SetCertificateRsp.md)

[19. Test for CHUNK_SEND_ACK](doc/19.ChunkSendAck.md)

[20. Test for CHUNK_RESPONSE](doc/20.ChunkResponse.md)

### Test Assumption

SPDM specification defines vendor-defined algorithms as implementation choice. The conformance test only validates the SPDM defined algorithms and it does not support the algorithm extensions including ExtAsym (1.0+), ExtHash (1.0+), AlgExternal (1.1+), OpaqueDataFmt0 (1.2+). If a device does not support SPDM defined algorithms and only supports the vendor-defined algorithms, then there is no way to run the test.

SPDM specification defines vendor-defined raw public key provision as implementation choice. The conformance test only validates the SPDM defined X.509 style public certificate chain and it does not support the vendor-defined raw public key. If a device does not support SPDM defined X.509 style public certificate chain (CERT_CAP) and only supports the vendor-defined raw public key (PUB_KEY_ID_CAP in 1.1+), then there is no way to run the certificate related test.

Some tests may require the responder to provision the environment. For example, mutual authentication may require the responder to provision the certificate from the requester. Pre-shared Key (PSK) exchange requires the requester and responder to provision the PSK. CSR retrival requires the requester to provide OEM-specific valid RequesterInfo. The prerequisites must be satisfied if the responder chooses to run these tests.

The device is not in update mode during test.

Some tests rely on the basic SPDM infrastructure. For example, RESPOND_IF_READY is used for ERROR(ResponseNotReady) if the crypto timeout happens, ENCAPSULATED message is used if mutual authentication is needed, CHUNKING is used if the message is too long. Fail to support those SPDM infrastructure may cause the related test abort.

### Test Criteria

The test checks what is mandated in the SPDM specification.
If the test passes, there will be a PASS assertion. Otherwise, there will be a FAIL assertion.

Some features in SPDM specification are recommended or optional, but not mandated. Those features may be tested as well.
If the test passes, there will be a PASS assertion. If the feature is not implemented, there will NOT be a FAIL assertion.

Some SPDM flows (such as mutual authentication and responder initiated key update) are controlled and triggered by the responder. The flow may be tested. If the responder has such capabilities and triggers the flows, then the test will be performed. Otherwise the test will be ignored and will NOT be a FAIL assertion. Once the test is performed, a PASS assertion or FAIL assertion will be given.

### Test Not Covered

The test for SPDM vendor defined message is not covered.

## Test Configuration

TBD ...

## Test Implementation

The test cases implementation is based uon DMTF [libspdm](https://github.com/DMTF/libspdm). The test cases checkpoint has no assumption on libspdm implementation.

The test case implemenmtation supports below transport binding by default:

   The MCTP and secured MCTP :

   [DSP0275](https://www.dmtf.org/dsp/DSP0275)  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   [DSP0276](https://www.dmtf.org/dsp/DSP0276)  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0.pdf))

   The PCI DOE :

   PCI  Data Object Exchange (DOE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14143)

   PCI  Component Measurement and Authentication (CMA) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14236)

   PCI  Integrity and Data Encryption (IDE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/15149)

### Add other Transport Layer Binding

TBD ...

## Run Test

### Run Test with spdm-emu

TBD ...

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