/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "atecc_priv.h"
LOG_MODULE_DECLARE(ateccx08);

/** \brief Executes Read command, which reads either 4 or 32 bytes of data from
 *          a given slot, configuration zone, or the OTP zone.
 *
 *   When reading a slot or OTP, data zone must be locked and the slot
 *   configuration must not be secret for a slot to be successfully read.
 *
 *  \param[in]  device   Device context pointer
 *  \param[in]  zone     Zone to be read from device. Options are
 *                       ATCA_ZONE_CONFIG, ATCA_ZONE_OTP, or ATCA_ZONE_DATA.
 *  \param[in]  slot     Slot number for data zone and ignored for other zones.
 *  \param[in]  block    32 byte block index within the zone.
 *  \param[in]  offset   4 byte work index within the block. Ignored for 32 byte
 *                       reads.
 *  \param[out] data     Read data is returned here.
 *  \param[in]  len      Length of the data to be read. Must be either 4 or 32.
 *
 *  returns ATCA_SUCCESS on success, otherwise an error code.
 */
static int atecc_calib_read_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				 uint8_t block, uint8_t offset, uint8_t *data, uint8_t len)
{
	struct ateccx08_packet packet;
	int ret;
	uint16_t addr;

	if ((NULL == dev) || (NULL == data)) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}
	if ((len != 4u && len != 32u)) {
		LOG_ERR("Invalid length received");
		return -EINVAL;
	}
	if (ATCA_MAX_PACKET_SIZE < (ATCA_PACKET_OVERHEAD + len)) {
		LOG_ERR("Invalid size received");
		return -EINVAL;
	}
	/* The get address function checks the remaining variables */
	ret = atecc_calib_get_addr(zone, slot, block, offset, &addr);
	if (ret < 0) {
		LOG_ERR("atecc_calib_get_addr - failed: %d", ret);
		return ret;
	}

	/* If there are 32 bytes to read, then OR the bit into the mode */
	if (len == ATCA_BLOCK_SIZE) {
		zone = zone | ATCA_ZONE_READWRITE_32;
	}

	/* build a read command */
	packet.param1 = zone;
	packet.param2 = addr;

	ret = atCommand(ATCA_READ, &packet, 0, 0);
	if (ret < 0) {
		LOG_ERR("atCommand - failed: %d", ret);
		return ret;
	}
	ret = atecc_calib_execute_command(dev, &packet);
	if (ret < 0) {
		LOG_ERR("atecc_calib_execute_command - failed: %d", ret);
		return ret;
	}

	(void)memcpy(data, &packet.data[1], len);

	return ret;
}

/** \brief Executes Read command, which reads the 9 byte serial number of the
 *          device from the config zone.
 *
 *  \param[in]  device         Device context pointer
 *  \param[out] serial_number  9 byte serial number is returned here.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atecc_calib_read_serial_number(const struct device *dev, uint8_t *serial_number)
{
	int ret;
	uint8_t read_buf[ATCA_BLOCK_SIZE];

	if (NULL == serial_number) {
		LOG_ERR("NULL pointer received");
		return -EFAULT;
	}

	ret = atecc_calib_read_zone(dev, ATCA_ZONE_CONFIG, 0, 0, 0, read_buf, ATCA_BLOCK_SIZE);
	if (ret < 0) {
		LOG_ERR("atecc_calib_read_zone - failed: %d", ret);
		return ret;
	}

	(void)memcpy(&serial_number[0], &read_buf[0], 4);
	(void)memcpy(&serial_number[4], &read_buf[8], 5);

	return ret;
}

/** \brief Used to read an arbitrary number of bytes from any zone configured
 *          for clear reads.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  zone    Zone to read data from. Option are ATCA_ZONE_CONFIG(0),
 *                      ATCA_ZONE_OTP(1), or ATCA_ZONE_DATA(2).
 *  \param[in]  slot    Slot number to read from if zone is ATCA_ZONE_DATA(2).
 *                      Ignored for all other zones.
 *  \param[in]  offset  Byte offset within the zone to read from.
 *  \param[out] data    Read data is returned here.
 *  \param[in]  length  Number of bytes to read starting from the offset.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atecc_calib_read_bytes_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				size_t offset, uint8_t *data, size_t length)
{
	int ret;
	size_t zone_size = 0;
	uint8_t read_buf[32];
	size_t data_idx = 0;
	size_t cur_block = 0;
	size_t cur_offset = 0;
	uint8_t read_size = ATCA_BLOCK_SIZE;
	size_t read_buf_idx = 0;
	size_t copy_length = 0;
	size_t read_offset = 0;

	if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA) {
		LOG_ERR("Invalid zone received");
		return -EINVAL;
	}
	if (zone == ATCA_ZONE_DATA && slot > 15u) {
		LOG_ERR("Invalid slot received");
		return -EINVAL;
	}
	if (length > 416u || offset > 416u) {
		LOG_ERR("Invalid length/offset received");
		return -EINVAL;
	}

	struct ateccx08_data *dev_data = dev->data;

	if ((zone == ATCA_ZONE_OTP || zone == ATCA_ZONE_DATA) && !dev_data->is_locked_data) {
		LOG_ERR("OTP and data zone not locked, couldn't read");
		return -EPERM;
	}

	if (length == 0u) {
		return 0; /* Always succeed reading 0 bytes */
	}

	if (data == NULL) {
		LOG_ERR("NULL pointer received");
		return -EINVAL;
	}

	ret = atecc_calib_get_zone_size(zone, slot, &zone_size);
	if (ret < 0) {
		LOG_ERR("atecc_calib_get_zone_size - failed: %d", ret);
		return ret;
	}

	/* Can't read past the end of a zone */
	if (offset + length > zone_size) {
		LOG_ERR("Invalid parameter received");
		return -EINVAL;
	}

	cur_block = offset / ATCA_BLOCK_SIZE;

	while (data_idx < length) {
		/* coverity[cert_int30_c_violation:FALSE]  overflow will not happen as the
		 * limits are checked
		 */
		if (read_size == ATCA_BLOCK_SIZE &&
		    zone_size - cur_block * ATCA_BLOCK_SIZE < ATCA_BLOCK_SIZE) {
			/* We have less than a block to read and can't read past the end of
			 * the zone, switch to word reads
			 */
			read_size = ATCA_WORD_SIZE;
			cur_offset = ((data_idx + offset) / ATCA_WORD_SIZE) %
				     (ATCA_BLOCK_SIZE / ATCA_WORD_SIZE);
		}

		/* Read next chunk of data */
		ret = atecc_calib_read_zone(dev, zone, slot, (uint8_t)cur_block,
					    (uint8_t)cur_offset, read_buf, read_size);
		if (ret < 0) {
			LOG_ERR("atecc_calib_read_zone - failed: %d", ret);
			return ret;
		}

		/* Calculate where in the read buffer we need data from */
		read_offset = cur_block * ATCA_BLOCK_SIZE + cur_offset * ATCA_WORD_SIZE;
		if (read_offset < offset) {
			read_buf_idx = offset -
				       read_offset; /* Read data starts before the requested chunk*/
		} else {
			read_buf_idx = 0; /* Read data is within the requested chunk */
		}
		/* Calculate how much data from the read buffer we want to copy */
		if (length - data_idx < read_size - read_buf_idx) {
			copy_length = length - data_idx;
		} else {
			copy_length = read_size - read_buf_idx;
		}

		(void)memcpy(&data[data_idx], &read_buf[read_buf_idx], copy_length);
		data_idx += copy_length;
		if (read_size == ATCA_BLOCK_SIZE) {
			cur_block += 1u;
		} else {
			cur_offset += 1u;
		}
	}

	return ret;
}
