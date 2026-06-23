#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Include the actual production header
#include "library/spdm_responder_conformance_test_lib/spdm_responder_test_2_capabilities.h"

START_TEST(test_data_transfer_size_bounds)
{
    // Invariant: data_transfer_size must not cause out-of-bounds memory access
    uint32_t payloads[] = {
        0xFFFFFFFF,  // Exploit case: maximum attacker-controlled value
        0x10000000,  // Boundary case: large but not maximum
        1024         // Valid case: reasonable size
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        // Create test context with attacker-controlled size
        spdm_test_context_t test_context;
        spdm_test_buffer_t test_buffer;
        
        memset(&test_context, 0, sizeof(test_context));
        memset(&test_buffer, 0, sizeof(test_buffer));
        
        test_buffer.data_transfer_size = payloads[i];
        test_context.test_buffer = &test_buffer;
        
        // Call the actual production function
        spdm_responder_test_2_capabilities(&test_context);
        
        // Property: No out-of-bounds write occurred
        // This is verified by the test framework's memory checking
        // If bounds were violated, the test would crash or fail via sanitizer
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_data_transfer_size_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}