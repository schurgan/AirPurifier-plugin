"""
<plugin key="XiaomiAirPurifierMulti" name="Xiaomi Air Purifier (Multi)" author="Alex" version="1.0.1">
    <description>
        Multi-device plugin for Xiaomi Air Purifier 2 / 2S using MiIO UDP protocol (no python-miio, no cryptography).
        Features: Power, AQI, Mode selector, Filter life %.
    </description>
    <params>
        <param field="Address" label="IPs (comma separated)" width="300px" required="true" default="192.168.178.29,192.168.178.30"/>
        <param field="Mode1" label="Tokens (comma separated, 32 hex each)" width="420px" required="true" default="token1,token2"/>
        <param field="Mode2" label="Names (optional, comma separated)" width="300px" required="false" default="Air Purifier 2,Air Purifier 2S"/>
        <param field="Mode3" label="Poll every X seconds" width="80px" required="true" default="30"/>
        <param field="Mode6" label="Debug" width="75px">
            <options>
                <option label="True" value="Debug"/>
                <option label="False" value="Normal" default="true"/>
            </options>
        </param>
    </params>
</plugin>
"""

import Domoticz
import socket
import struct
import time
import json
import hashlib
import threading
import queue
from typing import Any, Dict, List, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    AES = None
    pad = None
    unpad = None


def split_csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()


def log_debug(enabled: bool, msg: str) -> None:
    if enabled:
        Domoticz.Debug(msg)


def update_device(unit: int, n: int, s: str) -> None:
    if unit in Devices:
        if Devices[unit].nValue != n or Devices[unit].sValue != str(s):
            Devices[unit].Update(nValue=n, sValue=str(s))


class MiioDevice:
    """
    Minimal MiIO UDP implementation for Xiaomi devices (AES-CBC using token-derived key/iv).
    """

    def __init__(self, ip: str, token_hex: str, debug: bool = False, timeout: float = 2.0):
        self.ip = ip
        self.port = 54321
        self.debug = debug
        self.timeout = timeout

        token_hex = token_hex.strip().lower()
        if len(token_hex) != 32:
            raise ValueError("Token must be 32 hex chars")

        self.token = bytes.fromhex(token_hex)
        self.key = md5(self.token)
        self.iv = md5(self.key + self.token)

        self.device_id = 0
        self.stamp = 0
        self.msg_id = 1

    def _sock(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def handshake(self) -> bool:
        # Classic MiIO hello packet: 0x2131, len=0x0020, rest = 0xFF
        pkt = bytes.fromhex("21310020" + "ff" * 28)

        try:
            s = self._sock()
            try:
                s.sendto(pkt, (self.ip, self.port))
                data, _ = s.recvfrom(4096)
            finally:
                s.close()
        except Exception as e:
            log_debug(self.debug, f"[{self.ip}] Handshake failed: {e}")
            return False

        if len(data) < 32:
            return False

        magic, length = struct.unpack_from(">HH", data, 0)
        if magic != 0x2131:
            return False

        self.device_id = struct.unpack_from(">I", data, 8)[0]
        self.stamp = struct.unpack_from(">I", data, 12)[0]

        log_debug(self.debug, f"[{self.ip}] Handshake OK device_id={self.device_id} stamp={self.stamp}")
        return True

    def _encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return cipher.encrypt(pad(plaintext, 16, style="pkcs7"))

    def _decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")

    def _checksum(self, header16: bytes, payload_enc: bytes) -> bytes:
        return hashlib.md5(header16 + self.token + payload_enc).digest()

    def _build_packet(self, payload_json: Dict[str, Any]) -> bytes:
        if self.device_id == 0:
            if not self.handshake():
                raise RuntimeError("Handshake failed")

        payload_plain = json.dumps(payload_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload_enc = self._encrypt(payload_plain)

        length = 32 + len(payload_enc)
        hdr = bytearray(32)
        struct.pack_into(">HH", hdr, 0, 0x2131, length)
        struct.pack_into(">I", hdr, 4, 0)
        struct.pack_into(">I", hdr, 8, self.device_id)
        struct.pack_into(">I", hdr, 12, self.stamp)

        header16 = bytes(hdr[0:16])
        hdr[16:32] = self._checksum(header16, payload_enc)

        return bytes(hdr) + payload_enc

    def _send_recv(self, payload_json: Dict[str, Any]) -> Dict[str, Any]:
        pkt = self._build_packet(payload_json)

        s = self._sock()
        try:
            s.sendto(pkt, (self.ip, self.port))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        if len(data) < 32:
            raise RuntimeError("Bad response length")

        payload_enc = data[32:]
        if not payload_enc:
            return {}

        payload_plain = self._decrypt(payload_enc)
        return json.loads(payload_plain.decode("utf-8", errors="replace"))

    def call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        mid = self.msg_id
        self.msg_id += 1
        req = {"id": mid, "method": method, "params": params}
        log_debug(self.debug, f"[{self.ip}] -> {req}")
        resp = self._send_recv(req)
        log_debug(self.debug, f"[{self.ip}] <- {resp}")
        return resp

    def get_props(self, props: List[str]) -> List[Any]:
        # For purifiers typically returns list in same order as requested
        resp = self.call("get_prop", props)
        res = resp.get("result", [])
        if isinstance(res, list):
            return res
        return []

    def set_power(self, on: bool) -> None:
        self.call("set_power", ["on" if on else "off"])

    def set_mode(self, mode: str) -> None:
        # mode: "auto"|"silent"|"favorite"|"idle"
        self.call("set_mode", [mode])


class Plugin:
    STRIDE = 100  # unit spacing per device

    # local units
    U_AQI = 1
    U_POWER = 10
    U_MODE = 11
    U_FILTER_LIFE = 21

    def __init__(self):
        self.debug = False
        self.poll_seconds = 30
        self.next_poll = 0

        self.devices: Dict[int, MiioDevice] = {}
        self.names: Dict[int, str] = {}

        self.q: queue.Queue = queue.Queue()
        self.worker = threading.Thread(target=self._worker, name="XAPWorker", daemon=True)

    def _unit(self, pid: int, local: int) -> int:
        return (pid - 1) * self.STRIDE + local

    def _pid(self, unit: int) -> int:
        return (unit // self.STRIDE) + 1

    def _local(self, unit: int) -> int:
        return unit % self.STRIDE

    def onStart(self) -> None:
        if AES is None:
            Domoticz.Error("pycryptodome fehlt! Installiere: sudo python3 -m pip install -U pycryptodome")
            return

        self.debug = (Parameters["Mode6"] == "Debug")
        Domoticz.Debugging(1 if self.debug else 0)

        ips = split_csv(Parameters["Address"])
        toks = split_csv(Parameters["Mode1"])
        names = split_csv(Parameters.get("Mode2", ""))

        if len(ips) < 1 or len(ips) != len(toks):
            Domoticz.Error("IPs und Tokens müssen gleich viele sein (kommagetrennt).")
            return

        try:
            self.poll_seconds = max(10, int(Parameters["Mode3"]))
        except Exception:
            self.poll_seconds = 30

        self.devices.clear()
        self.names.clear()

        for idx, (ip, tok) in enumerate(zip(ips, toks), start=1):
            pid = idx
            name = names[pid - 1] if (pid - 1) < len(names) else f"Air Purifier {pid}"
            self.names[pid] = name
            self.devices[pid] = MiioDevice(ip=ip, token_hex=tok, debug=self.debug, timeout=2.0)

        for pid in self.devices.keys():
            self._create_devices(pid)

        self.worker.start()
        self.next_poll = 0
        Domoticz.Heartbeat(10)
        Domoticz.Log(f"XiaomiAirPurifierMulti gestartet: {len(self.devices)} Geräte")

    def _create_devices(self, pid: int) -> None:
        name = self.names[pid]

        u = self._unit(pid, self.U_AQI)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - AQI", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;AQI"}, Used=1).Create()

        u = self._unit(pid, self.U_POWER)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Power", Unit=u, TypeName="Switch", Used=1).Create()

        u = self._unit(pid, self.U_MODE)
        if u not in Devices:
            options = {
                "LevelActions": "||||",
                "LevelNames": "Idle|Silent|Favorite|Auto",
                "LevelOffHidden": "false",
                "SelectorStyle": "0"
            }
            Domoticz.Device(Name=f"{name} - Mode", Unit=u, TypeName="Selector Switch",
                            Switchtype=18, Options=options, Used=1).Create()

        u = self._unit(pid, self.U_FILTER_LIFE)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Filter %", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;%"}, Used=1).Create()

    def onCommand(self, Unit: int, Command: str, Level: int, Hue: int) -> None:
        pid = self._pid(Unit)
        local = self._local(Unit)
        self.q.put(("cmd", pid, local, Command, Level))

    def onHeartbeat(self) -> None:
        self.q.put(("poll",))

    def _worker(self) -> None:
        while True:
            msg = self.q.get()
            try:
                if msg[0] == "poll":
                    self._poll_if_due()
                elif msg[0] == "cmd":
                    _, pid, local, cmd, level = msg
                    self._handle_command(pid, local, cmd, level)
            except Exception as e:
                Domoticz.Error(f"Worker Fehler: {e}")
            finally:
                self.q.task_done()

    def _poll_if_due(self) -> None:
        if int(time.time()) < self.next_poll:
            return
        self.next_poll = int(time.time()) + self.poll_seconds

        for pid, dev in self.devices.items():
            name = self.names.get(pid, f"Air Purifier {pid}")
            try:
                # Common props for Purifier 2/2S
                # power: "on"/"off"
                # aqi: number
                # mode: "auto"/"silent"/"favorite"/"idle"
                # filter1_life: percent
                props = ["power", "aqi", "mode", "filter1_life"]
                res = dev.get_props(props)
                if len(res) < 4:
                    raise RuntimeError(f"get_prop returned {res}")

                power, aqi, mode, flife = res[0], res[1], res[2], res[3]

                # AQI
                update_device(self._unit(pid, self.U_AQI), 0, str(aqi if aqi is not None else ""))

                # Power
                p = str(power).lower()
                if p == "on":
                    update_device(self._unit(pid, self.U_POWER), 1, "On")
                elif p == "off":
                    update_device(self._unit(pid, self.U_POWER), 0, "Off")

                # Mode -> selector level
                lvl = self._mode_to_level(mode)
                if lvl is not None:
                    update_device(self._unit(pid, self.U_MODE), 1, str(lvl))

                # Filter life %
                if flife is not None:
                    update_device(self._unit(pid, self.U_FILTER_LIFE), 0, str(flife))

            except Exception as e:
                Domoticz.Error(f"{name} Poll Fehler: {e}")

    def _mode_to_level(self, mode_val: Any) -> Optional[int]:
        m = str(mode_val).lower()
        if "idle" in m:
            return 0
        if "silent" in m:
            return 10
        if "favorite" in m:
            return 20
        if "auto" in m:
            return 30
        return None

    def _level_to_mode(self, level: int) -> str:
        if level == 0:
            return "idle"
        if level == 10:
            return "silent"
        if level == 20:
            return "favorite"
        return "auto"

    def _handle_command(self, pid: int, local: int, command: str, level: int) -> None:
        if pid not in self.devices:
            return

        dev = self.devices[pid]

        if local == self.U_POWER:
            want_on = str(command).strip().lower() == "on"
            dev.set_power(want_on)
            self.next_poll = 0

        elif local == self.U_MODE:
            try:
                lvl = int(level)
            except Exception:
                lvl = 30
            dev.set_mode(self._level_to_mode(lvl))
            self.next_poll = 0


_plugin = Plugin()


def onStart():
    _plugin.onStart()


def onHeartbeat():
    _plugin.onHeartbeat()


def onCommand(Unit, Command, Level, Hue):
    _plugin.onCommand(Unit, Command, Level, Hue)
