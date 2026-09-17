/**
 *  Copyright Notice:
 *  Copyright 2021-2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/SPDM-Responder-Validator/blob/main/LICENSE.md
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

/*
 * Filter slot_mask down to slots that are usable for the given key usage.
 *
 * If MULTI_KEY_CONN_RSP is false, slot_mask is returned unchanged.
 * If MULTI_KEY_CONN_RSP is true, a slot is kept only if its DIGESTS.CertModel is not None,
 * and, when key_usage_bit is non-zero, its DIGESTS.KeyUsageMask has key_usage_bit set.
 */
uint8_t spdm_test_filter_valid_slot_mask (void *spdm_context, uint8_t slot_mask,
                                          uint16_t key_usage_bit)
{
    libspdm_data_parameter_t parameter;
    size_t data_size;
    bool multi_key_conn_rsp;
    spdm_certificate_info_t cert_info;
    spdm_key_usage_bit_mask_t key_usage_bit_mask;
    uint8_t slot_id;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    multi_key_conn_rsp = false;
    data_size = sizeof(multi_key_conn_rsp);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                     &multi_key_conn_rsp, &data_size);
    if (!multi_key_conn_rsp) {
        return slot_mask;
    }

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((slot_mask & (1 << slot_id)) == 0) {
            continue;
        }

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
        parameter.additional_data[0] = slot_id;
        cert_info = 0;
        data_size = sizeof(cert_info);
        libspdm_get_data(spdm_context, LIBSPDM_DATA_PEER_CERT_INFO, &parameter, &cert_info,
                         &data_size);
        if (cert_info == SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE) {
            slot_mask &= (uint8_t)~(1 << slot_id);
            continue;
        }

        if (key_usage_bit != 0) {
            key_usage_bit_mask = 0;
            data_size = sizeof(key_usage_bit_mask);
            libspdm_get_data(spdm_context, LIBSPDM_DATA_PEER_KEY_USAGE_BIT_MASK, &parameter,
                             &key_usage_bit_mask, &data_size);
            if ((key_usage_bit_mask & key_usage_bit) == 0) {
                slot_mask &= (uint8_t)~(1 << slot_id);
            }
        }
    }

    return slot_mask;
}

uint8_t spdm_test_get_first_slot_id (uint8_t slot_mask)
{
    uint8_t slot_id;

    for (slot_id = 0; slot_id < SPDM_MAX_SLOT_COUNT; slot_id++) {
        if ((slot_mask & (0x1 << slot_id)) != 0) {
            return slot_id;
        }
    }

    return SPDM_MAX_SLOT_COUNT;
}
