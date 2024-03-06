/*
 * Copyright (c) 2024 Vogl Electronic GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Driver for Microchip ATECCX08 I2C EEPROMs.
 */

#include "atecc_priv.h"
LOG_MODULE_REGISTER(ateccx08);

int eeprom_ateccx08_set_zone(const struct device *dev, uint8_t zone)
{
	if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA) {
		LOG_ERR("Invalid zone received");
		return -EINVAL;
	}
	struct ateccx08_data *data = dev->data;

	data->std_zone = zone;
	return 0;
}

int eeprom_ateccx08_set_slot(const struct device *dev, uint8_t slot)
{
	if (slot > 15u) {
		LOG_ERR("Invalid slot received");
		return -EINVAL;
	}
	struct ateccx08_data *data = dev->data;

	data->std_slot = slot;
	return 0;
}

static size_t eeprom_ateccx08_size(const struct device *dev)
{
	size_t size = 0;
	struct ateccx08_data *at_data = dev->data;

	atecc_calib_get_zone_size(at_data->std_zone, at_data->std_slot, &size);
	return size;
}

static int eeprom_ateccx08_write(const struct device *dev, off_t offset, const void *data,
				 size_t len)
{
	const struct ateccx08_config *cfg = dev->config;
	struct ateccx08_data *at_data = dev->data;

	if (cfg->readonly) {
		LOG_ERR("attempt to write to read-only device");
		return -EACCES;
	}

	return atecc_calib_write_bytes_zone(dev, at_data->std_zone, at_data->std_slot, offset, data,
					    len);
}

static int eeprom_ateccx08_read(const struct device *dev, off_t offset, void *data, size_t len)
{
	struct ateccx08_data *at_data = dev->data;

	return atecc_calib_read_bytes_zone(dev, at_data->std_zone, at_data->std_slot, offset, data,
					   len);
}

static int eeprom_ateccx08_init(const struct device *dev)
{
	const struct ateccx08_config *config = dev->config;

	if (!device_is_ready(config->i2c.bus)) {
		LOG_ERR("parent bus device not ready");
		return -EINVAL;
	}

	struct ateccx08_data *data = dev->data;

	data->std_zone = 1;
	data->std_slot = 0;

	int ret = atecc_calib_update_lock(dev);

	if (ret < 0) {
		LOG_ERR("atecc_calib_update_lock - failed: %d", ret);
		return ret;
	}

	LOG_DBG("Config lock status: %d", data->is_locked_config);
	LOG_DBG("Data lock status: %d", data->is_locked_data);

	return ret;
}

static const struct eeprom_driver_api ateccx08_driver_api = {
	.read = &eeprom_ateccx08_read,
	.write = &eeprom_ateccx08_write,
	.size = &eeprom_ateccx08_size,
};

#define INST_DT_ATECCX08(inst, t) DT_INST(inst, microchip_atecc##t)

#define EEPROM_ATECCX08_DEVICE(n, t)                                                               \
	static const struct ateccx08_config atecc##t##_config_##n = {                              \
		.i2c = I2C_DT_SPEC_GET(INST_DT_ATECCX08(n, t)),                                    \
		.readonly = DT_PROP(INST_DT_ATECCX08(n, t), read_only),                            \
		.wakedelay = DT_PROP(INST_DT_ATECCX08(n, t), wake_delay),                          \
		.retries = DT_PROP(INST_DT_ATECCX08(n, t), retries)};                              \
	static struct ateccx08_data atecc##t##_data_##n;                                           \
	DEVICE_DT_DEFINE(INST_DT_ATECCX08(n, t), &eeprom_ateccx08_init, NULL,                      \
			 &atecc##t##_data_##n, &atecc##t##_config_##n, POST_KERNEL,                \
			 CONFIG_EEPROM_INIT_PRIORITY, &ateccx08_driver_api)

#define EEPROM_ATECC608_DEVICE(n) EEPROM_ATECCX08_DEVICE(n, 608)
#define EEPROM_ATECC508_DEVICE(n) EEPROM_ATECCX08_DEVICE(n, 508)

#define CALL_WITH_ARG(arg, expr) expr(arg);

#define INST_DT_ATECCX08_FOREACH(t, inst_expr)                                                     \
	LISTIFY(DT_NUM_INST_STATUS_OKAY(microchip_atecc##t), CALL_WITH_ARG, (), inst_expr)

#ifdef CONFIG_EEPROM_ATECC608
INST_DT_ATECCX08_FOREACH(608, EEPROM_ATECC608_DEVICE);
#endif

#ifdef CONFIG_EEPROM_ATECC508
INST_DT_ATECCX08_FOREACH(608, EEPROM_ATECC508_DEVICE);
#endif
