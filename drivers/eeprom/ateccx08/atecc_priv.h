/*
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ATECC_PRIV_H_
#define ATECC_PRIV_H_

#include <zephyr/drivers/eeprom.h>
#include <zephyr/drivers/eeprom/ateccx08.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#include "atecc_def.h"

#define LOG_LEVEL CONFIG_EEPROM_LOG_LEVEL
#include <zephyr/logging/log.h>

/* ATECCX08 word address values*/
#define ATECCX08_WA_Reset   0x00U /* Reset word address value */
#define ATECCX08_WA_Sleep   0x01U /* Sleep word address value */
#define ATECCX08_WA_Idle    0x02U /* Idle word address value */
#define ATECCX08_WA_Command 0x03U /* Command word address value */

enum ateccx08_opcode {
	ATCA_CHECKMAC = 0x28U,
	ATCA_DERIVE_KEY = 0x1CU,
	ATCA_INFO = 0x30U,
	ATCA_GENDIG = 0x15U,
	ATCA_GENKEY = 0x40U,
	ATCA_LOCK = 0x17U,
	ATCA_MAC = 0x08U,
	ATCA_NONCE = 0x16U,
	ATCA_PRIVWRITE = 0x46U,
	ATCA_RANDOM = 0x1BU,
	ATCA_READ = 0x02U,
	ATCA_SIGN = 0x41U,
	ATCA_UPDATE_EXTRA = 0x20U,
	ATCA_VERIFY = 0x45U,
	ATCA_WRITE = 0x12U,
	ATCA_ECDH = 0x43U,
	ATCA_COUNTER = 0x24U,
	ATCA_DELETE = 0x13U,
	ATCA_SHA = 0x47U,
	ATCA_AES = 0x51U,
	ATCA_KDF = 0x56U,
	ATCA_SECUREBOOT = 0x80U,
	ATCA_SELFTEST = 0x77U
};

#define ATCA_ZONE_CONFIG ATECC_ZONE_CONFIG
#define ATCA_ZONE_OTP    ATECC_ZONE_OTP
#define ATCA_ZONE_DATA   ATECC_ZONE_DATA

#define ATCA_MAX_PACKET_SIZE (198U) /* Maximum packet size in bytes */

#define ATCA_POLLING_INIT_TIME_MSEC 1

#define ATCA_POLLING_FREQUENCY_TIME_MSEC 2

#define ATCA_POLLING_MAX_TIME_MSEC 2500

typedef enum {
	ATCA_DEVICE_STATE_UNKNOWN = 0,
	ATCA_DEVICE_STATE_SLEEP,
	ATCA_DEVICE_STATE_IDLE,
	ATCA_DEVICE_STATE_ACTIVE
} ateccx08_device_state;

struct ateccx08_packet {
	uint8_t reserved;
	uint8_t txsize;
	uint8_t opcode;
	uint8_t param1;
	uint16_t param2;
	uint8_t data[ATCA_MAX_PACKET_SIZE - 6];
	uint8_t execTime;
} __packed;

struct ateccx08_config {
	struct i2c_dt_spec i2c;
	bool readonly;
	uint16_t wakedelay;
	uint16_t retries;
};

struct ateccx08_data {
	uint8_t std_zone;
	uint8_t std_slot;
	bool is_locked_config;
	bool is_locked_data;
	ateccx08_device_state device_state;
	struct k_mutex lock;
};

int atCheckCrc(const uint8_t *response);

int atCommand(enum ateccx08_opcode opcode, struct ateccx08_packet *packet, bool has_mac,
	      uint16_t write_context_size);

int atecc_calib_wakeup(const struct device *dev);

int atecc_calib_sleep(const struct device *dev);

int atecc_calib_idle(const struct device *dev);

int atecc_calib_execute_command(const struct device *dev, struct ateccx08_packet *packet);

int atecc_calib_get_zone_size(uint8_t zone, uint16_t slot, size_t *size);

int atecc_calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset,
			 uint16_t *addr);

int atecc_calib_updateextra(const struct device *dev, uint8_t mode, uint16_t new_value);

int atecc_calib_update_lock(const struct device *dev);

#endif /* ATECC_PRIV_H_ */
