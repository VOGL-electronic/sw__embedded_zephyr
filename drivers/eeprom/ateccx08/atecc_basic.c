/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

void atecc_CRC(size_t length, const uint8_t *data, uint8_t *crc_le)
{
	size_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;

	for (counter = 0; counter < length; counter++) {
		for (shift_register = 0x01; shift_register > 0x00u; shift_register <<= 1) {
			data_bit = ((data[counter] & shift_register) != 0u) ? 1u : 0u;
			crc_bit = (uint8_t)(crc_register >> 15);
			crc_register <<= 1;
			if (data_bit != crc_bit) {
				crc_register ^= polynom;
			}
		}
	}
	crc_le[0] = (uint8_t)(crc_register & 0x00FFu);
	crc_le[1] = (uint8_t)(crc_register >> 8u);
}

static void atCalcCrc(struct ateccx08_packet *packet)
{
	uint8_t length;
	uint8_t *crc;

	packet->param2 = sys_cpu_to_le16(packet->param2);

	/* coverity[cert_int31_c_violation] txsize is properly set so length will not underflow */
	length = (packet->txsize - (uint8_t)ATCA_CRC_SIZE) & UINT8_MAX;

	/* calculate crc location */
	crc = &packet->data[length - ((uint8_t)ATCA_CMD_SIZE_MIN - (uint8_t)ATCA_CRC_SIZE)];

	/* stuff CRC into packet */
	atecc_CRC(length, &(packet->txsize), crc);
}

int atCheckCrc(const uint8_t *response)
{
	uint8_t crc[ATCA_CRC_SIZE];
	uint8_t count = response[ATCA_COUNT_IDX];

	count -= (uint8_t)ATCA_CRC_SIZE;
	atecc_CRC(count, response, crc);

	if ((crc[0] == response[count]) && (crc[1] == response[count + 1u])) {
		return 0;
	}
	return -EBADMSG;
}

static int hal_check_wake(const uint8_t *response, int response_size)
{
	const uint8_t expected_response[4] = {0x04, 0x11, 0x33, 0x43};
	const uint8_t selftest_fail_resp[4] = {0x04, 0x07, 0xC4, 0x40};

	if (response_size != 4) {
		LOG_ERR("ATCA_WAKE_FAILED");
		return -EIO;
	}
	if (memcmp(response, expected_response, 4) == 0) {
		return 0;
	}
	if (memcmp(response, selftest_fail_resp, 4) == 0) {
		LOG_ERR("ATCA_STATUS_SELFTEST_ERROR");
		return -EIO;
	}
	return -EIO;
}

int atecc_calib_wakeup(const struct device *dev)
{
	const struct ateccx08_config *cfg = dev->config;
	struct ateccx08_data *dev_data = dev->data;
	int ret = -1;
	uint8_t second_byte = 0x01; /* I2C general call should not interpreted as an addr write */

	uint32_t i2c_cfg_temp;
	uint32_t wake;
	uint16_t rxlen;
	uint16_t retries = cfg->retries;

	do {
		i2c_get_config(cfg->i2c.bus, &i2c_cfg_temp);
		if (I2C_SPEED_GET(i2c_cfg_temp) != I2C_SPEED_STANDARD) {
			uint32_t i2c_cfg_temp_1 = i2c_cfg_temp & ~I2C_SPEED_SET(0);

			i2c_cfg_temp_1 |= I2C_SPEED_SET(I2C_SPEED_STANDARD);
			i2c_configure(cfg->i2c.bus, i2c_cfg_temp_1);
		}
		i2c_write(cfg->i2c.bus, (uint8_t *)&second_byte, sizeof(second_byte), 0x00);
		k_busy_wait(cfg->wakedelay);

		rxlen = (uint16_t)sizeof(wake);

		ret = i2c_read_dt(&cfg->i2c, (uint8_t *)&wake, rxlen);
		if (ret < 0) {
			continue;
		}
		ret = hal_check_wake((uint8_t *)&wake, (int)rxlen);
		if (ret < 0) {
			continue;
		} else {
			dev_data->device_state = ATCA_DEVICE_STATE_ACTIVE;
			break;
		}
	} while (retries-- > 0);

	if (I2C_SPEED_GET(i2c_cfg_temp) != I2C_SPEED_STANDARD) {
		i2c_configure(cfg->i2c.bus, i2c_cfg_temp);
	}

	return ret;
}

int atecc_calib_sleep(const struct device *dev)
{
	const struct ateccx08_config *cfg = dev->config;
	struct ateccx08_data *dev_data = dev->data;
	uint8_t command = ATECCX08_WA_Sleep;
	int ret;

	ret = i2c_write_dt(&cfg->i2c, &command, 1);
	if (ret < 0) {
		LOG_ERR("Failed to write to device: %d", ret);
		dev_data->device_state = ATCA_DEVICE_STATE_UNKNOWN;
		return ret;
	}
	dev_data->device_state = ATCA_DEVICE_STATE_SLEEP;
	return ret;
}

int atecc_calib_idle(const struct device *dev)
{
	const struct ateccx08_config *cfg = dev->config;
	struct ateccx08_data *dev_data = dev->data;
	uint8_t command = ATECCX08_WA_Idle;
	int ret;

	ret = i2c_write_dt(&cfg->i2c, &command, 1);
	if (ret < 0) {
		LOG_ERR("Failed to write to device: %d", ret);
		dev_data->device_state = ATCA_DEVICE_STATE_UNKNOWN;
		return ret;
	}
	dev_data->device_state = ATCA_DEVICE_STATE_IDLE;
	return ret;
}

int atecc_calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t *addr)
{
	uint8_t mem_zone = (uint8_t)(zone & 0x03u);

	if (addr == NULL) {
		LOG_ERR("Invalid length received");
		return -EINVAL;
	}
	if ((mem_zone != ATCA_ZONE_CONFIG) && (mem_zone != ATCA_ZONE_DATA) &&
	    (mem_zone != ATCA_ZONE_OTP)) {
		LOG_ERR("Invalid zone received");
		return -EINVAL;
	}

	/* Initialize the addr to 00 */
	*addr = 0;
	/* Mask the offset */
	offset = offset & (uint8_t)0x07;
	if ((mem_zone == ATCA_ZONE_CONFIG) || (mem_zone == ATCA_ZONE_OTP)) {
		*addr = ((uint16_t)block) << 3;
		*addr |= offset;
	} else { /* ATCA_ZONE_DATA */
		*addr = slot << 3;
		*addr |= offset;
		*addr |= ((uint16_t)block) << 8;
	}

	return 0;
}

int atecc_calib_get_zone_size(uint8_t zone, uint16_t slot, size_t *size)
{
	if (size == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	switch (zone) {
	case ATCA_ZONE_CONFIG:
		*size = 128;
		break;
	case ATCA_ZONE_OTP:
		*size = 64;
		break;
	case ATCA_ZONE_DATA:
		if (slot < 8u) {
			*size = 36;
		} else if (slot == 8u) {
			*size = 416;
		} else if (slot < 16u) {
			*size = 72;
		} else {
			LOG_ERR("Invalid slot received");
			return -EINVAL;
		}
		break;
	default:
		LOG_ERR("Invalid zone received");
		return -EINVAL;
	}

	return 0;
}

int atCommand(enum ateccx08_opcode opcode, struct ateccx08_packet *packet, bool has_mac,
	      uint16_t write_context_size)
{
	switch (opcode) {
	case ATCA_CHECKMAC:
		packet->txsize = CHECKMAC_COUNT;
		break;

	case ATCA_DERIVE_KEY:
		if (has_mac) {
			packet->txsize = DERIVE_KEY_COUNT_LARGE;
		} else {
			packet->txsize = DERIVE_KEY_COUNT_SMALL;
		}
		break;

	case ATCA_INFO:
		packet->txsize = INFO_COUNT;
		break;

	case ATCA_GENDIG:
		if (packet->param1 == GENDIG_ZONE_SHARED_NONCE) { /* shared nonce mode */
			packet->txsize = GENDIG_COUNT + 32u;
		} else if (!has_mac) {
			packet->txsize =
				GENDIG_COUNT +
				4u; /* noMac keys use 4 bytes of OtherData in calculation */
		} else {
			packet->txsize = GENDIG_COUNT;
		}
		break;

	case ATCA_GENKEY:
		if ((packet->param1 & GENKEY_MODE_PUBKEY_DIGEST) == GENKEY_MODE_PUBKEY_DIGEST) {
			packet->txsize = GENKEY_COUNT_DATA;
		} else {
			packet->txsize = GENKEY_COUNT;
		}
		break;

	case ATCA_LOCK:
		packet->txsize = LOCK_COUNT;
		break;

	case ATCA_MAC:
		if ((packet->param1 & MAC_MODE_BLOCK2_TEMPKEY) == 0u) {
			packet->txsize = MAC_COUNT_LONG;
		} else {
			packet->txsize = MAC_COUNT_SHORT;
		}
		break;

	case ATCA_NONCE:
		uint8_t calc_mode = packet->param1 & NONCE_MODE_MASK;

		if ((calc_mode == NONCE_MODE_SEED_UPDATE ||
		     calc_mode == NONCE_MODE_NO_SEED_UPDATE ||
		     calc_mode == NONCE_MODE_GEN_SESSION_KEY)) {
			/* Calculated nonce mode, 20 byte NumInm */
			packet->txsize = NONCE_COUNT_SHORT;
		} else if (calc_mode == NONCE_MODE_PASSTHROUGH) {
			/* Pass-through nonce mode */
			if ((packet->param1 & NONCE_MODE_INPUT_LEN_MASK) ==
			    NONCE_MODE_INPUT_LEN_64) {
				/* 64 byte NumIn */
				packet->txsize = NONCE_COUNT_LONG_64;
			} else {
				/* 32 byte NumIn */
				packet->txsize = NONCE_COUNT_LONG;
			}
		} else {
			return -EINVAL;
		}
		break;

	case ATCA_PRIVWRITE:
		packet->txsize = PRIVWRITE_COUNT;
		break;

	case ATCA_RANDOM:
		packet->txsize = RANDOM_COUNT;
		break;

	case ATCA_READ:
		packet->txsize = READ_COUNT;
		break;

	case ATCA_SIGN:
		packet->txsize = SIGN_COUNT;
		break;

	case ATCA_UPDATE_EXTRA:
		packet->txsize = UPDATE_COUNT;
		break;

	case ATCA_VERIFY:
		switch (packet->param1 & VERIFY_MODE_MASK) {
		case VERIFY_MODE_STORED:
			packet->txsize = VERIFY_256_STORED_COUNT;
			break;

		case VERIFY_MODE_VALIDATE_EXTERNAL:
			packet->txsize = VERIFY_256_EXTERNAL_COUNT;
			break;

		case VERIFY_MODE_EXTERNAL:
			packet->txsize = VERIFY_256_EXTERNAL_COUNT;
			break;

		case VERIFY_MODE_VALIDATE:
		case VERIFY_MODE_INVALIDATE:
			packet->txsize = VERIFY_256_VALIDATE_COUNT;
			break;

		default:
			return -EINVAL;
		}
		break;

	case ATCA_WRITE:
		packet->txsize = 7;

		if ((packet->param1 & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32) {
			packet->txsize += ATCA_BLOCK_SIZE;
		} else {
			packet->txsize += ATCA_WORD_SIZE;
		}

		if (has_mac) {
			packet->txsize += WRITE_MAC_SIZE;
		}
		break;

	case ATCA_ECDH:
		packet->txsize = ECDH_COUNT;
		break;

	case ATCA_COUNTER:
		packet->txsize = COUNTER_COUNT;
		break;

	case ATCA_DELETE:
		packet->txsize = DELETE_COUNT;
		break;

	case ATCA_SHA:
		switch (packet->param1 & SHA_MODE_MASK) {
		case SHA_MODE_SHA256_START: /* START */
		case SHA_MODE_HMAC_START:
		case 0x03: /* SHA_MODE_SHA256_PUBLIC || SHA_MODE_ECC204_HMAC_START */
			packet->txsize = ATCA_CMD_SIZE_MIN;
			break;

		case SHA_MODE_SHA256_UPDATE: /* UPDATE */
			packet->txsize =
				(uint8_t)((ATCA_CMD_SIZE_MIN + packet->param2) & UINT8_MAX);
			break;

		case SHA_MODE_SHA256_END: /* END */
		case SHA_MODE_HMAC_END:
			/* check the given packet for a size variable in param2.  If it is > 0, it
			 * should be 0-63, incorporate that size into the packet
			 */
			packet->txsize =
				(uint8_t)((ATCA_CMD_SIZE_MIN + packet->param2) & UINT8_MAX);
			break;

		case SHA_MODE_WRITE_CONTEXT:
			packet->txsize =
				(uint8_t)((ATCA_CMD_SIZE_MIN + write_context_size) & UINT8_MAX);
			break;

		default:
			packet->txsize = ATCA_CMD_SIZE_MIN;
			break;
		}
		break;

	case ATCA_AES:
		packet->txsize = ATCA_CMD_SIZE_MIN;

		if ((packet->param1 & AES_MODE_OP_MASK) == AES_MODE_GFM) {
			packet->txsize += ATCA_AES_GFM_SIZE;
		} else {
			packet->txsize += AES_DATA_SIZE;
		}
		break;

	case ATCA_KDF:
		if ((packet->param1 & KDF_MODE_ALG_MASK) == KDF_MODE_ALG_AES) {
			/* AES algorithm has a fixed message size */
			packet->txsize = ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + AES_DATA_SIZE;
		} else {
			/* All other algorithms encode message size in the last byte of details */
			packet->txsize = (ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + packet->data[3]) &
					 UINT8_MAX;
		}
		break;

	case ATCA_SECUREBOOT:
		packet->txsize = ATCA_CMD_SIZE_MIN;

		/* variable transmit size based on mode encoding */
		switch (packet->param1 & SECUREBOOT_MODE_MASK) {
		case SECUREBOOT_MODE_FULL:
		case SECUREBOOT_MODE_FULL_COPY:
			packet->txsize += (SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE);
			break;

		case SECUREBOOT_MODE_FULL_STORE:
			packet->txsize += SECUREBOOT_DIGEST_SIZE;
			break;

		default:
			return -EINVAL;
		}
		break;

	case ATCA_SELFTEST:
		packet->txsize = SELFTEST_COUNT;
		break;

	default:
		return -EINVAL;
	}

	packet->opcode = opcode;
	atCalcCrc(packet);
	return 0;
}

int atecc_calib_updateextra(const struct device *dev, uint8_t mode, uint16_t new_value)
{
	struct ateccx08_packet packet;
	int ret;

	if (dev == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	/* Build command */
	(void)memset(&packet, 0, sizeof(packet));
	packet.param1 = mode;
	packet.param2 = new_value;

	ret = atCommand(ATCA_UPDATE_EXTRA, &packet, 0, 0);
	if (ret < 0) {
		LOG_ERR("atCommand (UpdateExtra)- failed: %d", ret);
		return ret;
	}

	ret = atecc_calib_execute_command(dev, &packet);
	if (ret < 0) {
		LOG_ERR("atecc_calib_execute_command (UpdateExtra) - failed: %d", ret);
		return ret;
	}

	return ret;
}
