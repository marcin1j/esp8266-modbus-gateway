from struct import pack, unpack, pack_into
from time import sleep_ms
from binascii import hexlify
import socket
import select
import sys


LOG = 0
logh = None
logsrv = None

def set_log(level):
    global logging, LOG, logh, logsrv
    LOG = level
    if level:
        import logging

        logh = logging.getLogger("modbus.handler")
        logh.setLevel(level)

        logsrv = logging.getLogger("modbus.server")
        logsrv.setLevel(level)



def _log_hexbin(prefix, data):
    if LOG and logh.level <= logging.DEBUG:
        logh.debug("%s: %s", prefix, hexlify(data).decode())

def _crc16_modbus(buf, offset, length):
    result = 0xFFFF

    for i in range(offset, offset+length):
        result ^= buf[i]

        for _ in range(0, 8):
            if result & 1:
                result >>= 1
                result ^= 0xA001
            else:
                result >>= 1

    return result


class ModbusBuffer:
    def __init__(self):
        self._buf = memoryview(bytearray(128))

        self._pdu_len = None
        self.buf_tcp_mbap = self._buf[0:7]      # Fixed size
        self.buf_tcp_adu = None
        self.buf_rtu_adu = None
        self.buf_rtu_adu_full = self._buf[6:]   # Fixed size
        self.buf_pdu = None

    def set_pdu_len(self, pdu_len):
        self._pdu_len = pdu_len

        self.buf_tcp_adu = self._buf[0:self._pdu_len+7]
        self.buf_rtu_adu = self._buf[6:self._pdu_len+9]
        self.buf_pdu = self._buf[7:self._pdu_len+7]

    def parse_tcp_mbap(self):
        self.tcp_transaction_id, tcp_protocol_id, pdu_a_len = unpack('!HHH', self._buf)
        if tcp_protocol_id is not 0 or pdu_a_len > 0xFF:
            return False

        self.set_pdu_len(pdu_a_len-1)
        return True

    def parse_pdu(self):
        self.pdu_function = self._buf[7]

    def store_tcp_mbap(self):
        pack_into('!HHH', self._buf, 0, self.tcp_transaction_id, 0, self._pdu_len+1)

    def store_rtu_exception(self, code):
        self._buf[7] = self.pdu_function ^ 0x80
        self._buf[8] = code
        self.set_pdu_len(2)

        self.store_rtu_adu_crc()

    def store_rtu_adu_crc(self):
        crc = _crc16_modbus(self._buf, 6, self._pdu_len+1)
        pack_into('H', self._buf, self._pdu_len+7, crc)
        return crc

    def validate_crc(self):
        calculated = _crc16_modbus(self._buf, 6, self._pdu_len+1)
        received, = unpack('H', self._buf[self._pdu_len+7:])

        return calculated == received

class ModbusTimeout(Exception):
    pass

class ModbusShortRead(Exception):
    def __init__(self, nb_read, nb_expected):
        self.nb_read = nb_read
        self.nb_expected = nb_expected


class ModbusGateway:
    def __init__(self, uart, pin_de, pin_led = None, wdt_feed = None):
        self._buf = ModbusBuffer()

        self._uart = uart
        self._pin_de = pin_de
        self._pin_led = pin_led
        self._wdt_feed_cb = wdt_feed

    def _uart_discard(self):
        total = 0

        remaing = self._uart.any()
        while remaing:
            total += self._uart.readinto(self._buf._buf, remaing)
            remaing = self._uart.any()

        return total

    def _uart_read_exactly(self, buf, nbytes):
        rb = self._uart.readinto(buf, nbytes)
        if rb is None:
            raise ModbusTimeout()
        elif rb < nbytes:
            raise ModbusShortRead(rb, nbytes)

    def _maybe_blink_led(self):
        if self._pin_led is None:
            return

        self._pin_led(0)
        sleep_ms(1)
        self._pin_led(1)

    def _handle_request(self, conn):

        uart_garbage = self._uart_discard()
        if uart_garbage:
            if LOG:
                logh.warning("Discarded %d bytes from UART buffer", uart_garbage)

        rd = conn.readinto(self._buf.buf_tcp_mbap)
        if not rd:
            return None

        _log_hexbin("TCP request: MBAP", self._buf.buf_tcp_mbap[0:rd])
        if rd < 7:
            if LOG:
                logh.warning("TCP request: short MBAP read %d/%d", rd, len(self._buf.buf_tcp_mbap))
            return False
        elif not self._buf.parse_tcp_mbap():
            if LOG:
                logh.warning("TCP request: invalid/suspicious MBAP")
            return False

        rd = conn.readinto(self._buf.buf_pdu)
        if rd < len(self._buf.buf_pdu):
            if LOG:
                logh.warning("TCP request: short PDU read %d/%d", rd, len(self._buf.buf_pdu))
            return False
        self._buf.parse_pdu()


        _log_hexbin("TCP request: PDU", self._buf.buf_pdu)

        self._buf.store_rtu_adu_crc()
        _log_hexbin("RTU request: ADU", self._buf.buf_rtu_adu)


        self._maybe_blink_led()

        # Write RTU ADU
        self._pin_de.on()
        self._uart.write(self._buf.buf_rtu_adu)
        sleep_ms(10)
        self._pin_de.off()


        try:
            if LOG:
                logh.debug("RTU response: reading address+function")
            buf_adu = self._buf.buf_rtu_adu_full
            self._uart_read_exactly(buf_adu, 2)

            addr = buf_adu[0]
            func = buf_adu[1]

            if LOG:
                logh.debug("RTU response: address is %d and function is %02x", addr, func)

            if func in (1, 2, 3, 4):
                if LOG:
                    logh.debug("RTU response: reading data length")
                self._uart_read_exactly(buf_adu[2:], 1)
                pl = buf_adu[2]
                if LOG:
                    logh.debug("RTU response: reading %d data bytes", pl)
                self._uart_read_exactly(buf_adu[3:], pl+2)

                self._buf.set_pdu_len(3+pl-1)
            elif func in (5, 15, 6, 16):
                if LOG:
                    logh.debug("RTU response: reading 4 data bytes")
                self._uart_read_exactly(buf_adu[2:], 4+2)
                self._buf.set_pdu_len(2+4-1)
            elif func & 0x80:
                # Exception
                if LOG:
                    logh.debug("RTU response: reading 1 data byte")
                self._uart_read_exactly(buf_adu[2:], 1)
                self._buf.set_pdu_len(2+1-1)
                self._buf.store_rtu_adu_crc()
            else:
                if LOG:
                    logh.warning("RTU response: unsupported function %02x", func)
                self._buf.store_rtu_exception(0x01)
        except ModbusTimeout:
            if LOG:
                logh.warning("RTU read timeout")
            self._buf.store_rtu_exception(0x0b)
        except ModbusShortRead as e:
            if LOG:
                logh.warning("RTU read: short read %d/%d", e.nb_read, e.nb_expected)
            self._buf.store_rtu_exception(0x04)

        _log_hexbin("RTU read ADU", self._buf.buf_rtu_adu)
        if not self._buf.validate_crc():
            if LOG:
                logh.warning("RTU read: invalid CRC")
            self._buf.store_rtu_exception(0x04)

        self._buf.store_tcp_mbap()
        _log_hexbin("TCP response: MBAP", self._buf.buf_tcp_mbap)
        _log_hexbin("TCP response: PDU", self._buf.buf_pdu)

        conn.write(self._buf.buf_tcp_adu)

        return True


    def _handle_or_unregister(self, conn, addr):
        success = False
        try:
            if LOG:
                logsrv.info("Starting to serve %s:%d", *addr)
            success = self._handle_request(conn)
            if LOG and success is not None:
                logsrv.info("Served %s:%d", *addr)
            else:
                logsrv.info("Remote %s:%d closed connection", *addr)
        except OSError as e:
            if LOG:
                logh.exc(e, "Network exception serving request")

        if LOG and success is False:
            logsrv.debug("Network communication failed, closing socket")

        if not success:
            self._conn_close(conn)
            conn.close()

    def _conn_add(self, conn, addr):
        self._p.register(conn, select.POLLIN)
        self._conns[id(conn)] = addr

    def _conn_close(self, conn):
            self._p.unregister(conn)
            del self._conns[id(conn)]
            conn.close()

    def _wdt_feed(self):
        if self._wdt_feed_cb:
            self._wdt_feed_cb()

    def serve(self):
        self._s = socket.socket()
        self._p = select.poll()
        self._conns = {}

        try:
            if LOG:
                logsrv.debug("Opening server socket")

            self._s.bind(('0.0.0.0', 502))
            self._s.listen(1)
            self._p.register(self._s, select.POLLIN)

            if LOG:
                logsrv.debug("Entering server loop")

            while True:
                for sock, event in self._p.ipoll(1000):
                    self._wdt_feed()
                    if LOG:
                        logsrv.debug("Handling event %d on %s", event, sock)
                    if sock is self._s:
                        conn, addr = sock.accept()
                        if LOG:
                            logsrv.info("New connection from %s", addr)
                        self._conn_add(conn, addr)

                        self._handle_or_unregister(conn, addr)
                    else:
                        addr = self._conns[id(sock)]
                        self._handle_or_unregister(sock, addr)

                self._wdt_feed()

        finally:
            self._s.close()
            del self._s
            del self._p

# Uncomment to enable logging. Requires micropython-logging package installed.
#set_log(10) # Debug level
