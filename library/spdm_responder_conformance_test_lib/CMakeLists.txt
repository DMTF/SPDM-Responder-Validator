cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal/${ARCH}
                    ${SPDM_RESPONDER_VALIDATOR_DIR}/include
                    ${COMMON_TEST_FRAMEWORK_DIR}/include
)

SET(src_spdm_responder_conformance_test_lib
    spdm_responder_test.c
    spdm_responder_test_1_version.c
    spdm_responder_test_2_capabilities.c
    spdm_responder_test_3_algorithms.c
    spdm_responder_test_support.c
)

ADD_LIBRARY(spdm_responder_conformance_test_lib STATIC ${src_spdm_responder_conformance_test_lib})
