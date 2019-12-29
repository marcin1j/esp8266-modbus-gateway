from time import sleep
import sys
from machine import Pin, reset, WDT

from modbus import ModbusGateway


print("Closing serial terminal in 5 seconds")
sleep(5)
print("Closing terminal right now!")


# Machine UART
from machine import UART
from uos import dupterm
from esp import osdebug
osdebug(None)
dupterm(None, 1)
# Serial port settings: 9600 8N1. Change as needed.
uart = UART(0, 9600, bits = 8, parity = 0, stop = 1, timeout = 250, timeout_char = 10, rxbuf = 128)


# RS485 driver enable pin
pin_de = Pin(5, Pin.OPEN_DRAIN)     # Wemos D1 Mini: D1
# Board LED pin
pin_led = Pin(2, Pin.OPEN_DRAIN)    # Wemos D1 Mini: D4/LED

# Soft watchdog. To disable replace following line with
# wtd_feed = None
wdt_feed = WDT().feed


gateway = ModbusGateway(uart, pin_de, pin_led, wdt_feed)
try:
    gateway.serve()
except Exception as e:
    sys.print_exception(e)

print("Server loop exited!")
