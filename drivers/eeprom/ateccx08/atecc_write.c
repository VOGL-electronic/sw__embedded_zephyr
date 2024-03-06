/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

static int atecc_calib_write(const struct device *dev, uint8_t zone, uint16_t address,
			     const uint8_t *value, const uint8_t *mac)
{
	struct ateccx08_packet packet;
	int ret;
	bool require_mac = false;

	if ((dev == NULL) || (value == NULL)) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

#if (ATCA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + 32u + MAC_SIZE))

	if (((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32) && (mac != NULL)) {
		LOG_ERR("Unsupported parameter");
		return -EINVAL;
	}
#endif

	/* Build the write command */
	packet.param1 = zone;
	packet.param2 = address;
	if ((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32) {
		/* 32-byte write */
		(void)memcpy(packet.data, value, 32);
		/* Only 32-byte writes can have a MAC */
		if (mac != NULL) {
			(void)memcpy(&packet.data[32], mac, 32);
		}
	} else {
		/* 4-byte write */
		(void)memcpy(packet.data, value, 4);
	}

	if ((NULL != mac) && ((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32)) {
		require_mac = true;
	}

	ret = atCommand(ATCA_WRITE, &packet, require_mac, 0);
	if (ret < 0) {
		LOG_ERR("atCommand - failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_execute_command(dev, &packet);
	if (ret < 0) {
		LOG_ERR("atecc_calib_execute_command - failed: %d", ret);
		return ret;
	}

	return ret;
}

static int atecc_calib_write_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				  uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len)
{
	int ret;
	uint16_t addr;

	/* Check the input parameters */
	if (data == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	if (len != 4u && len != 32u) {
		LOG_ERR("Invalid length received");
		return -EINVAL;
	}

	struct ateccx08_data *dev_data = dev->data;

	if (zone == ATCA_ZONE_OTP || zone == ATCA_ZONE_DATA) {
		if (!dev_data->is_locked_config) {
			LOG_ERR("Configuration zone not locked, couldn't write");
			return -EPERM;
		} else if (dev_data->is_locked_data) {
			LOG_ERR("OTP and data zone locked, couldn't write");
			return -EPERM;
		}
	}

	if (zone == ATCA_ZONE_CONFIG && dev_data->is_locked_config) {
		LOG_ERR("Configuration zone locked, couldn't write");
		return -EPERM;
	}

	/* The get address function checks the remaining variables */
	ret = atecc_calib_get_addr(zone, slot, block, offset, &addr);
	if (ret < 0) {
		LOG_ERR("atecc_calib_get_addr - failed: %d", ret);
		return ret;
	}

	/* If there are 32 bytes to write, then xor the bit into the mode */
	if (len == ATCA_BLOCK_SIZE) {
		zone = zone | ATCA_ZONE_READWRITE_32;
	}

	return atecc_calib_write(dev, zone, addr, data, NULL);
}

int atecc_calib_write_bytes_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				 size_t offset_bytes, const uint8_t *data, size_t length)
{
	int ret;
	size_t zone_size = 0;
	size_t data_idx = 0;
	size_t cur_block = 0;
	size_t cur_word = 0;

	if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA) {
		LOG_ERR("Invalid zone received");
		return -EINVAL;
	}
	if (zone == ATCA_ZONE_DATA && slot > 15u) {
		LOG_ERR("Invalid slot received");
		return -EINVAL;
	}
	if (length == 0u) {
		return 0; /* Always succeed writing 0 bytes */
	}
	if (data == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}
	if (offset_bytes % ATCA_WORD_SIZE != 0u || length % ATCA_WORD_SIZE != 0u) {
		LOG_ERR("Invalid length/offset received");
		return -EINVAL;
	}

	ret = atecc_calib_get_zone_size(zone, slot, &zone_size);
	if (ret < 0) {
		LOG_ERR("atecc_calib_get_zone_size - failed: %d", ret);
		return ret;
	}
	if (offset_bytes + length > zone_size) {
		LOG_ERR("Invalid parameter received");
		return -EINVAL;
	}

	cur_block = offset_bytes / ATCA_BLOCK_SIZE;
	cur_word = (offset_bytes % ATCA_BLOCK_SIZE) / ATCA_WORD_SIZE;

	while (data_idx < length) {
		/* The last item makes sure we handle the selector, user extra, and lock
		 * bytes in the config properly
		 */
		if (cur_word == 0u && length - data_idx >= ATCA_BLOCK_SIZE &&
		    !(zone == ATCA_ZONE_CONFIG && cur_block == 2u)) {
			ret = atecc_calib_write_zone(dev, zone, slot, (uint8_t)cur_block, 0,
						     &data[data_idx], ATCA_BLOCK_SIZE);
			if (ret < 0) {
				LOG_ERR("atecc_calib_write_zone - failed: %d", ret);
				return ret;
			}
			data_idx += ATCA_BLOCK_SIZE;
			cur_block += 1u;
		} else {
			/* Skip trying to change UserExtra, Selector, LockValue, and
			 * LockConfig which require the UpdateExtra command to change
			 */
			if (!(zone == ATCA_ZONE_CONFIG && cur_block == 2u && cur_word == 5u)) {
				ret = atecc_calib_write_zone(dev, zone, slot, (uint8_t)cur_block,
							     (uint8_t)cur_word, &data[data_idx],
							     ATCA_WORD_SIZE);
				if (ret < 0) {
					LOG_ERR("atecc_calib_write_zone - failed: %d", ret);
					return ret;
				}
			}
			data_idx += ATCA_WORD_SIZE;
			cur_word += 1u;
			if (cur_word == ATCA_BLOCK_SIZE / ATCA_WORD_SIZE) {
				cur_block += 1u;
				cur_word = 0u;
			}
		}
	}

	return ret;
}

int atecc_calib_write_config_zone(const struct device *dev, const uint8_t *config_data)
{
	int ret;
	size_t config_size = 0;

	if (config_data == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	/* Get config zone size for the device */
	ret = atecc_calib_get_zone_size(ATCA_ZONE_CONFIG, 0, &config_size);
	if (ret < 0) {
		LOG_ERR("atecc_calib_get_zone_size - failed: %d", ret);
		return ret;
	}

	/* Write config zone excluding UserExtra and Selector */
	ret = atecc_calib_write_bytes_zone(dev, ATCA_ZONE_CONFIG, 0, 16, &config_data[16],
					   config_size - 16u);
	if (ret < 0) {
		LOG_ERR("atecc_calib_write_bytes_zone - failed: %d", ret);
		return ret;
	}

	/* Write the UserExtra and Selector. This may fail if either value is already non-zero. */
	ret = atecc_calib_updateextra(dev, UPDATE_MODE_USER_EXTRA, config_data[84]);
	if (ret < 0) {
		LOG_ERR("atecc_calib_updateextra - failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_updateextra(dev, UPDATE_MODE_SELECTOR, config_data[85]);
	if (ret < 0) {
		LOG_ERR("atecc_calib_updateextra - failed: %d", ret);
		return ret;
	}

	return ret;
}

int atecc_calib_write_config_counter(const struct device *dev, uint16_t counter_id,
				     uint32_t counter_value)
{
	uint16_t lin_a, lin_b, bin_a, bin_b;
	uint8_t bytes[8];
	uint8_t idx = 0;

	if (counter_id > 1u || counter_value > COUNTER_MAX_VALUE) {
		LOG_ERR("Invalid parameter received");
		return -EINVAL;
	}

	/* coverity[misra_c_2012_rule_12_2_violation] Shifting more than 15 bits doesnot harm the
	 * functionality
	 */
	lin_a = (uint16_t)((0xFFFFu >> (counter_value % 32u)) & UINT16_MAX);
	lin_b = (uint16_t)((0xFFFFu >>
			    ((counter_value >= 16u) ? (counter_value - 16u) % 32u : 0u)) &
			   UINT16_MAX);
	bin_a = (uint16_t)(counter_value / 32u);
	bin_b = (counter_value >= 16u) ? ((uint16_t)((counter_value - 16u) / 32u)) : 0u;

	bytes[idx++] = (uint8_t)(lin_a >> 8u);
	bytes[idx++] = (uint8_t)(lin_a & 0xFFu);
	bytes[idx++] = (uint8_t)(lin_b >> 8u);
	bytes[idx++] = (uint8_t)(lin_b & 0xFFu);

	bytes[idx++] = (uint8_t)(bin_a >> 8u);
	bytes[idx++] = (uint8_t)(bin_a & 0xFFu);
	bytes[idx++] = (uint8_t)(bin_b >> 8u);
	bytes[idx] = (uint8_t)(bin_b & 0xFFu);

	return atecc_calib_write_bytes_zone(dev, ATCA_ZONE_CONFIG, 0,
					    52u + ((size_t)counter_id * 8u), bytes, sizeof(bytes));
}
