#!/usr/bin/env python3

import tinytuya

# /!\ CHANGE THESE VALUES /!\
# See: https://github.com/jasonacox/tinytuya#setup-wizard---getting-local-keys
# Get values (device ID, IP, key, version) from: python -m tinytuya wizard
d = tinytuya.OutletDevice(
    dev_id='',
    address='',
    #address='auto',
    local_key='',
    version=3.4)
#tinytuya.set_debug()
# Find the right Datapoint with d.status(), you can also read:
# https://github.com/dulfer/localtuya-device-datapoints?tab=readme-ov-file#device-dps
#print(d.status())
timer_datapoint = 9

# Power off after 2 minutes (so the PC can shutdown gently meanwhile)
print(d.set_timer(2 * 60, timer_datapoint))
