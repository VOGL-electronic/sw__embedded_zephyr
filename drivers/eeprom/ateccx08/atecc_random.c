/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

int atecc_calib_random(const struct device *dev, uint8_t *rand_out)
{
	struct ateccx08_packet packet;
	int ret;

	/* build an random command */
	packet.param1 = RANDOM_SEED_UPDATE;
	packet.param2 = 0x0000;

	ret = atCommand(ATCA_RANDOM, &packet, 0, 0);
	if (ret < 0) {
		LOG_ERR("atCommand - failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_execute_command(dev, &packet);
	if (ret < 0) {
		LOG_ERR("atecc_calib_execute_command - failed: %d", ret);
		return ret;
	}

	if (packet.data[ATCA_COUNT_IDX] != RANDOM_RSP_SIZE) {
		LOG_ERR("Unexpected response size");
		return -EBADMSG;
	}

	if (NULL != rand_out) {
		(void)memcpy(rand_out, &packet.data[ATCA_RSP_DATA_IDX], (size_t)RANDOM_NUM_SIZE);
	}

	return 0;
}
