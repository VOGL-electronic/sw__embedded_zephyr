/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

static int atecc_calib_info_base(const struct device *dev, uint8_t mode, uint16_t param2,
				 uint8_t *out_data)
{
	struct ateccx08_packet packet;
	int status;

	/* build an info command */
	packet.param1 = mode;
	packet.param2 = param2;

	atCommand(ATCA_INFO, &packet, 0, 0);

	status = atecc_calib_execute_command(dev, &packet);
	if (status < 0) {
		LOG_ERR("Failed to execute command: %d", status);
		return status;
	}

	uint8_t response = packet.data[ATCA_COUNT_IDX];

	if ((response != 0u) && (NULL != out_data)) {
		if (response >= 7u) {
			(void)memcpy(out_data, &packet.data[ATCA_RSP_DATA_IDX], 4);
		}
	}

	return status;
}

int atecc_calib_info(const struct device *dev, uint8_t *revision)
{
	if (revision == NULL) {
		return -ENOBUFS;
	}

	return atecc_calib_info_base(dev, INFO_MODE_REVISION, 0, revision);
}

int atecc_calib_info_get_latch(const struct device *dev, bool *state)
{
	int ret;
	uint8_t out_data[4];

	if (state == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	ret = atecc_calib_info_base(dev, INFO_MODE_VOL_KEY_PERMIT, 0, out_data);
	if (ret < 0) {
		LOG_ERR("atecc_calib_info_base - failed: %d", ret);
		return ret;
	}

	*state = (out_data[0] == 1u);

	return ret;
}

int atecc_calib_info_set_latch(const struct device *dev, bool state)
{
	uint16_t param2 = INFO_PARAM2_SET_LATCH_STATE;

	param2 |= state ? INFO_PARAM2_LATCH_SET : INFO_PARAM2_LATCH_CLEAR;
	return atecc_calib_info_base(dev, INFO_MODE_VOL_KEY_PERMIT, param2, NULL);
}
