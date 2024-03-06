/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

static int atecc_calib_lock(const struct device *dev, uint8_t mode, uint16_t summary_crc)
{
	struct ateccx08_packet packet;
	int ret;

	if (dev == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	/* build command for lock zone and send */
	(void)memset(&packet, 0, sizeof(packet));
	packet.param1 = mode;
	packet.param2 = summary_crc;

	ret = atCommand(ATCA_LOCK, &packet, 0, 0);
	if (ret < 0) {
		LOG_ERR("atCommand - failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_execute_command(dev, &packet);
	if (ret < 0) {
		LOG_ERR("atecc_calib_execute_command - failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_update_lock(dev);
	if (ret < 0) {
		LOG_ERR("atecc_calib_update_lock - failed: %d", ret);
		return ret;
	}

	return ret;
}

int atecc_calib_lock_config_zone(const struct device *dev)
{
	return atecc_calib_lock(dev, LOCK_ZONE_NO_CRC | LOCK_ZONE_CONFIG, 0);
}

int atecc_calib_lock_config_zone_crc(const struct device *dev, uint16_t summary_crc)
{
	return atecc_calib_lock(dev, LOCK_ZONE_CONFIG, summary_crc);
}

int atecc_calib_lock_data_zone(const struct device *dev)
{
	return atecc_calib_lock(dev, LOCK_ZONE_NO_CRC | LOCK_ZONE_DATA, 0);
}

int atecc_calib_lock_data_zone_crc(const struct device *dev, uint16_t summary_crc)
{
	return atecc_calib_lock(dev, LOCK_ZONE_DATA, summary_crc);
}

int atecc_calib_lock_data_slot(const struct device *dev, uint16_t slot)
{

	return atecc_calib_lock(dev, (uint8_t)((LOCK_ZONE_DATA_SLOT | (slot << 2)) & UINT8_MAX), 0);
}

static int atecc_calib_check_lock(const struct device *dev, bool *is_locked_config,
				  bool *is_locked_data)
{
	uint8_t data_lock[4];

	int ret = atecc_calib_read_bytes_zone(dev, ATCA_ZONE_CONFIG, 0, 84, data_lock,
					      sizeof(data_lock));
	if (ret < 0) {
		LOG_ERR("atecc_calib_read_bytes_zone - failed: %d", ret);
		return ret;
	}

	if (data_lock[2] == ATCA_UNLOCKED) {
		*is_locked_data = false;
	} else {
		*is_locked_data = true;
	}

	if (data_lock[3] == ATCA_UNLOCKED) {
		*is_locked_config = false;
	} else {
		*is_locked_config = true;
	}

	return ret;
}

int atecc_calib_update_lock(const struct device *dev)
{
	struct ateccx08_data *data = dev->data;

	return atecc_calib_check_lock(dev, &data->is_locked_config, &data->is_locked_data);
}

bool atecc_calib_is_locked_config(const struct device *dev)
{
	struct ateccx08_data *data = dev->data;

	return data->is_locked_config;
}
