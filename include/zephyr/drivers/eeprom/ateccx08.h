/*
 * Copyright (c) 2015-2020 Microchip Technology Inc.
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_EEPROM_ATECCX08_H_
#define ZEPHYR_INCLUDE_DRIVERS_EEPROM_ATECCX08_H_

#include <zephyr/drivers/eeprom.h>

#define ATECC_ZONE_CONFIG 0x00U
#define ATECC_ZONE_OTP    0x01U
#define ATECC_ZONE_DATA   0x02U

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set the zone for the EEPROM device.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param zone Zone to set: ATECC_ZONE_CONFIG(0), ATECC_ZONE_OTP(1), or
 *             ATECC_ZONE_DATA(2).
 *
 * @retval 0 on success
 * @retval -EINVAL if zone is invalid
 */
int eeprom_ateccx08_set_zone(const struct device *dev, uint8_t zone);

/**
 * @brief Set the slot for the EEPROM device.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param slot Slot to set.
 *
 * @retval 0 on success
 * @retval -EINVAL if slot is invalid
 */
int eeprom_ateccx08_set_slot(const struct device *dev, uint8_t slot);

/**
 * @brief Calculates CRC over the given raw data and returns the CRC in
 *        little-endian byte order.
 *
 * @param length Size of data not including the CRC byte positions
 * @param data Pointer to the data over which to compute the CRC
 * @param crc_le Pointer to the place where the two-bytes of CRC will be
 *               returned in little-endian byte order.
 */
void atecc_CRC(size_t length, const uint8_t *data, uint8_t *crc_le);

/**
 * @brief Use the Info command to get the device revision (DevRev).
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param revision Device revision is returned here (4 bytes).
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_info(const struct device *dev, uint8_t *revision);

/**
 * @brief Use the Info command to get the persistent latch current state for
 *        an ATECC608 device.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param state The state is returned here. Set (true) or Cler (false).
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_info_get_latch(const struct device *dev, bool *state);

/**
 * @brief Use the Info command to set the persistent latch state for an
 *        ATECC608 device.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param state Persistent latch state. Set (true) or clear (false).
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_info_set_latch(const struct device *dev, bool state);

/**
 * @brief Unconditionally (no CRC required) lock the config zone.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_lock_config_zone(const struct device *dev);

/**
 * @brief Lock the config zone with summary CRC.
 * The CRC is calculated over the entire config zone contents.
 * 128 bytes for ATECC devices. Lock will fail if the provided
 * CRC doesn't match the internally calculated one.
 *
 *  @param dev Pointer to the device structure for the driver instance.
 *  @param summary_crc Expected CRC over the config zone.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_lock_config_zone_crc(const struct device *dev, uint16_t summary_crc);

/**
 * @brief Unconditionally (no CRC required) lock the data zone (slots and OTP).
 *
 * ConfigZone must be locked and DataZone must be unlocked for the zone to be successfully
 * locked.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_lock_data_zone(const struct device *dev);

/**
 * @brief Lock the data zone (slots and OTP) with summary CRC.
 *
 * The CRC is calculated over the concatenated contents of all the slots and
 * OTP at the end. Private keys (KeyConfig.Private=1) are skipped. Lock will
 * fail if the provided CRC doesn't match the internally calculated one.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param summary_crc Expected CRC over the data zone.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_lock_data_zone_crc(const struct device *dev, uint16_t summary_crc);

/**
 * @brief Lock an individual slot in the data zone on an ATECC device. Not
 *        available for ATSHA devices. Slot must be configured to be slot
 *        lockable (KeyConfig.Lockable=1).
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param slot Slot to be locked in data zone.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_lock_data_slot(const struct device *dev, uint16_t slot);

/**
 * @brief Check the lock status of the configuration and data zones.
 *
 * @param dev Pointer to the device structure for the driver instance.
 *
 * @retval true if the configuration zone is locked
 * @retval false if the configuration zone is not locked
 */
bool atecc_calib_is_locked_config(const struct device *dev);

/**
 * @brief Executes Random command, which generates a 32 byte random number
 *        from the CryptoAuth device.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param rand_out 32 bytes of random data is returned here.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_random(const struct device *dev, uint8_t *rand_out);

/**
 * @brief Executes Read command, which reads the 9 byte serial number of the
 *        device from the config zone.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param serial_number  9 byte serial number is returned here.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_read_serial_number(const struct device *dev, uint8_t *serial_number);

/**
 * @brief Used to read an arbitrary number of bytes from any zone configured
 *        for clear reads.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param zone Zone to read data from. Option are ATECC_ZONE_CONFIG(0),
 *             ATECC_ZONE_OTP(1), or ATECC_ZONE_DATA(2).
 * @param slot Slot number to read from if zone is ATECC_ZONE_DATA(2).
 *             Ignored for all other zones.
 * @param offset Byte offset within the zone to read from.
 * @param data Read data is returned here.
 * @param length Number of bytes to read starting from the offset.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_read_bytes_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				size_t offset, uint8_t *data, size_t length);

/**
 * @brief Executes the Write command, which writes data into the
 * configuration, otp, or data zones with a given byte offset and
 * length. Offset and length must be multiples of a word (4 bytes).
 *
 * Config zone must be unlocked for writes to that zone. If data zone is
 * unlocked, only 32-byte writes are allowed to slots and OTP and the offset
 * and length must be multiples of 32 or the write will fail.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param zone Zone to write data to: ATECC_ZONE_CONFIG(0),
 *             ATECC_ZONE_OTP(1), or ATECC_ZONE_DATA(2).
 * @param slot If zone is ATECC_ZONE_DATA(2), the slot number to
 *             write to. Ignored for all other zones.
 * @param offset_bytes Byte offset within the zone to write to. Must be
 *                     a multiple of a word (4 bytes).
 * @param data Data to be written.
 * @param length Number of bytes to be written. Must be a multiple
 *               of a word (4 bytes).
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_write_bytes_zone(const struct device *dev, uint8_t zone, uint16_t slot,
				 size_t offset_bytes, const uint8_t *data, size_t length);

/**
 * @brief Executes the Write command, which writes the configuration zone.
 *
 * First 16 bytes are skipped as they are not writable. LockValue and
 * LockConfig are also skipped and can only be changed via the Lock
 * command.
 *
 * This command may fail if UserExtra and/or Selector bytes have
 * already been set to non-zero values.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param config_data  Data to the config zone data. This should be 128 bytes.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_write_config_zone(const struct device *dev, const uint8_t *config_data);

/**
 * @brief Initialize one of the monotonic counters in device with a specific
 *        value.
 *
 * The monotonic counters are stored in the configuration zone using a special
 * format. This encodes a binary count value into the 8 byte encoded value
 * required. Can only be set while the configuration zone is unlocked.
 *
 * @param dev Pointer to the device structure for the driver instance.
 * @param counter_id Counter to be written.
 * @param counter_value Counter value to set.
 *
 * @retval 0 on success, other error code otherwise
 */
int atecc_calib_write_config_counter(const struct device *dev, uint16_t counter_id,
				     uint32_t counter_value);
#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_EEPROM_ATECCX08_H_ */
