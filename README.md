# ESP8266 Modbus TCP/RTU gateway

This is a Modbus TCP to RTU gateway for ESP8266 microcontroller written in [MicroPython](http://micropython.org/).
Multiple persistent TCP connections are supported. There is watchdog timer that should reboot the controller in case anything goes wrong.

## Installation
First, you need ESP8266 with MicroPython onboard. Refer to official [MicroPython ESP8266 tutorial](https://docs.micropython.org/en/latest/esp8266/tutorial/index.html) for more details.
Setup WiFi connection and WebREPL. This is the most convenient way to transfer files into board flash. What's more important, this will be the only access to REPL console since hardware UART is used for Modbus communication.

Next review serial port settings (the default is `9600`, `8N1`) in `main.py` and change according to your needs. Transfer `modbus.py` and `main.py` into the board. For this you need `webrepl_cli.py` available from MicroPython [WebREPL repository](https://github.com/micropython/webrepl):
```bash
# webrepl_cli.py modbus.py 192.168.4.1:/
# webrepl_cli.py main.py 192.168.4.1:/
```

## Hardware connection
A TTL-RS485 converter is necessary for RS485 connection. Connect ESP `TX` pin to `DI` pin and ESP `RX` pin to `RO` pin. By default `D1` (`GPIO5`, you can change this in `main.py`) is used for driver enable control and needs to be connected to converter's `DE` (active high) and `RE` (active low) pins.


## Software part
The code is purposely _not_ using [uasyncio](https://github.com/micropython/micropython-lib/tree/master/uasyncio) library to avoid frequent memory allocation and possible fragmentation issues.
Request handler uses `readinto()` functions to read data in-place into a single static buffer of 128 bytes for TCP and RTU frames. This is the maximum supported TCP frame length. Maximum RTU frame length is 122 bytes. You can increase that if you want by raising buffer size.

### Watchdog timer
There is a watchdog timer with timeout between 1.6 and 3.2 seconds (see this [MicroPython issue](https://github.com/micropython/micropython/issues/2154)), reset on every Modbus TCP request and every 1000ms. If Modbus TCP master fails to send request and acknowledge response in watchdog timeout, it will reboot the board.

### Logging
By default logging is disabled. To enable logging, use `set_log()` function in `modbus.py`:
```python
set_log(10) # Debug level
```

Logging requires [micropython-logging](https://pypi.org/project/micropython-logging/) package installed. Refer to official MicroPython [package documentation](https://docs.micropython.org/en/latest/reference/packages.html) for details.

### Troubleshooting
When something goes wrong causing the code to hang or raise an unexpected exception, watchdog timer will promptly reboot the device. This is desired in normal use but makes debugging virtually impossible.
To disable watchdog timer pass `None` as `wdt_feed` to `ModbusGateway`. **It's important not to instantiate `WDT` class because this starts watchdog which can't be stopped afterwards.**

So in order to disable watchdog timer you need to edit `main.py` and replace

```python
wdt_feed = WDT().feed
```

with

```python
wdt_feed = None
```

Another point to consider is that debugging is tough without log messages so do yourself a favour installing [micropython-logging](https://pypi.org/project/micropython-logging/) package and enable logging as described in the previous part.
