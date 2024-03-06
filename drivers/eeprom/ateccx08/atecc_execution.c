/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

static int isATCAError(uint8_t *data)
{
	/* error packets are always 4 bytes long */
	if (data[0] == 0x04u) {
		switch (data[1]) {
		case 0x00: /* No Error */
			return 0;
		case 0x01: /* checkmac or verify failed */
			LOG_ERR("ATCA_CHECKMAC_VERIFY_FAILED");
			return -EIO;
		case 0x03: /* command received byte length, opcode or parameter was illegal */
			LOG_ERR("ATCA_PARSE_ERROR");
			return -EIO;
		case 0x05: /* computation error during ECC processing causing invalid results */
			LOG_ERR("ATCA_STATUS_ECC");
			return -EIO;
		case 0x07: /* chip is in self test failure mode */
			LOG_ERR("ATCA_STATUS_SELFTEST_ERROR");
			return -EIO;
		case 0x08: /* random number generator health test error */
			LOG_ERR("ATCA_HEALTH_TEST_ERROR");
			return -EIO;
		case 0x0f: /* chip can't execute the command */
			LOG_ERR("ATCA_EXECUTION_ERROR");
			return -EIO;
		case 0x11: /* chip was successfully woken up */
			LOG_ERR("ATCA_WAKE_SUCCESS");
			return -EIO;
		case 0xff: /* bad crc found (command not properly received by device) or other comm
			    * error
			    */
			LOG_ERR("ATCA_STATUS_CRC");
			return -EIO;
		default:
			LOG_ERR("ATCA_GEN_FAIL");
			return -EIO;
		}
	}

	return 0;
}

static int atecc_calib_execute_receive(const struct device *dev, uint8_t *rxdata,
				       size_t rxlength)
{
	const struct ateccx08_config *cfg = dev->config;
	int ret = 0;
	uint16_t read_length = 1;
	uint8_t word_address;

	word_address = 0;

	/* Read length bytes to know number of bytes to read */
	ret = i2c_read_dt(&cfg->i2c, rxdata, read_length);
	if (ret < 0) {
		return ret;
	}

	/*Calculate bytes to read based on device response*/
	read_length = rxdata[0];

	if (read_length > rxlength) {
		LOG_ERR("Buffer too small to read response");
		return ret;
	}

	if (read_length < 4u) {
		LOG_ERR("Invalid response length");
		return ret;
	}

	/* Read given length bytes from device */
	read_length -= 1u;

	ret = i2c_read_dt(&cfg->i2c, &rxdata[1], read_length);

	if (ret < 0) {
		LOG_ERR("Failed to read from device: %d", ret);
		return ret;
	}

	return ret;
}

int atecc_calib_execute_command(const struct device *dev, struct ateccx08_packet *packet)
{
	const struct ateccx08_config *cfg = dev->config;
	struct ateccx08_data *dev_data = dev->data;
	uint32_t execution_or_wait_time = ATCA_POLLING_INIT_TIME_MSEC;
	uint32_t max_delay_count = ATCA_POLLING_MAX_TIME_MSEC / ATCA_POLLING_FREQUENCY_TIME_MSEC;
	uint16_t retries = cfg->retries;
	int ret;

	packet->reserved = ATECCX08_WA_Command;

	do {
		if (dev_data->device_state != ATCA_DEVICE_STATE_ACTIVE) {
			atecc_calib_wakeup(dev);
		}

		ret = i2c_write_dt(&cfg->i2c, (uint8_t *)packet, (uint32_t)packet->txsize + 1u);
		if (ret < 0) {
			dev_data->device_state = ATCA_DEVICE_STATE_UNKNOWN;
		} else {
			dev_data->device_state = ATCA_DEVICE_STATE_ACTIVE;
			break;
		}
	} while (retries-- > 0);

	if (ret < 0) {
		LOG_ERR("Failed to write to device: %d", ret);
		return ret;
	}

	k_busy_wait(execution_or_wait_time * USEC_PER_MSEC);

	do {
		(void)memset(packet->data, 0, sizeof(packet->data));
		/* receive the response */
		ret = atecc_calib_execute_receive(dev, packet->data, sizeof(packet->data));
		if (ret == 0) {
			break;
		}

		LOG_DBG("try receive response again: %d", ret);

		/* delay for polling frequency time */
		k_busy_wait(ATCA_POLLING_FREQUENCY_TIME_MSEC * USEC_PER_MSEC);
	} while (max_delay_count-- > 0);

	if (atecc_calib_idle(dev) < 0) {
		dev_data->device_state = ATCA_DEVICE_STATE_UNKNOWN;
	}

	if (ret < 0) {
		return ret;
	}

	/* coverity[misra_c_2012_directive_4_14_violation:FALSE] Packet data is handled properly */
	ret = atCheckCrc(packet->data);
	if (ret < 0) {
		return ret;
	}

	ret = isATCAError(packet->data);
	if (ret < 0) {
		return ret;
	}

	return ret;
}
