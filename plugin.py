"""
<plugin key="XiaomiAirPurifierMulti" name="Xiaomi Air Purifier (Multi)" author="Alex+GPT" version="1.0.0" externallink="">
    <description>
        Multi-device plugin for Xiaomi Air Purifier 2 / 2S using MiIO protocol (no python-miio, no cryptography).
        Features: Power, Mode selector, AQI, Filter life %, Filter hours used.
    </description>
    <params>
        <param field="Address" label="IPs (comma separated)" width="300px" required="true" default="192.168.1.50,192.168.1.51"/>
        <param field="Mode1" label="Tokens (comma separated)" width="420px" required="true" default="token1,token2"/>
        <param field="Mode2" label="Names (optional, comma separated)" width="300px" required="false" default="Air Purifier 2,Air Purifier 2S"/>
        <param field="Mode3" label="Poll every X minutes" width="50px" required="true" default="1"/>
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
import threading
import queue
import json
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception as e:
    AES = None
    pad = None
    unpad = None


# ------------------------- Helpers -------------------------

def split_csv(v: str) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]

def md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()

def now_ts() -> int:
    return int(time.time())

def log_debug(enabled: bool, msg: str):
    if enabled:
        Domoticz.Debug(msg)

def update_device(unit: int, n: int, s: str):
    if unit in Devices:
        if Devices[unit].nValue != n or Devices[unit].sValue != str(s):
            Devices[unit].Update(nValue=n, sValue=str(s))


# ------------------------- MiIO minimal implementation -------------------------
# Based on MiIO UDP protocol (54321). Pure python AES-CBC using token-derived key/iv.

@dataclass
class MiioSession:
    device_id: int = 0
    stamp: int = 0  # timestamp from handshake


class MiioDevice:
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
        self.session = MiioSession()

        self._msg_id = 1

    def _sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def handshake(self) -> bool:
        # handshake: send 32 bytes with header, device_id=0, stamp=0, checksum=0xFFFFFFFF...
        # In practice: send magic + length, unknown fields 0, token bytes set to 0xFF
        pkt = bytearray(32)
        struct.pack_into(">HH", pkt, 0, 0x2131, 32)  # magic, length
        struct.pack_into(">I", pkt, 8, 0)           # device_id
        struct.pack_into(">I", pkt, 12, 0)          # stamp
        pkt[16:32] = b"\xFF" * 16

        try:
            with self._sock() as s:
                s.sendto(pkt, (self.ip, self.port))
                data, _ = s.recvfrom(4096)
        except Exception as e:
            log_debug(self.debug, f"[{self.ip}] Handshake failed: {e}")
            return False

        if len(data) < 32:
            return False

        magic, length = struct.unpack_from(">HH", data, 0)
        if magic != 0x2131 or length != len(data):
            return False

        dev_id = struct.unpack_from(">I", data, 8)[0]
        stamp = struct.unpack_from(">I", data, 12)[0]

        self.session.device_id = dev_id
        self.session.stamp = stamp
        log_debug(self.debug, f"[{self.ip}] Handshake OK: device_id={dev_id} stamp={stamp}")
        return True

    def _encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return cipher.encrypt(pad(plaintext, 16, style="pkcs7"))

    def _decrypt(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")

    def _checksum(self, header_16: bytes, payload: bytes) -> bytes:
        # checksum = MD5(header[0:16] + token + payload)
        return hashlib.md5(header_16 + self.token + payload).digest()

    def _build_packet(self, payload_json: Dict[str, Any]) -> bytes:
        if self.session.device_id == 0:
            if not self.handshake():
                raise RuntimeError("Handshake failed")

        payload_plain = json.dumps(payload_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload_enc = self._encrypt(payload_plain)

        length = 32 + len(payload_enc)
        pkt = bytearray(32)
        struct.pack_into(">HH", pkt, 0, 0x2131, length)
        struct.pack_into(">I", pkt, 4, 0)  # unknown/zero
        struct.pack_into(">I", pkt, 8, self.session.device_id)
        struct.pack_into(">I", pkt, 12, self.session.stamp)

        # checksum over header[0:16] + token + payload
        header_16 = bytes(pkt[0:16])
        csum = self._checksum(header_16, payload_enc)
        pkt[16:32] = csum

        return bytes(pkt) + payload_enc

    def _send_recv(self, payload_json: Dict[str, Any]) -> Dict[str, Any]:
        pkt = self._build_packet(payload_json)
        with self._sock() as s:
            s.sendto(pkt, (self.ip, self.port))
            data, _ = s.recvfrom(4096)

        if len(data) < 32:
            raise RuntimeError("Bad response length")

        payload_enc = data[32:]
        if not payload_enc:
            # Some replies may be empty; treat as ok
            return {}

        try:
            payload_plain = self._decrypt(payload_enc)
            return json.loads(payload_plain.decode("utf-8", errors="replace"))
        except Exception as e:
            raise RuntimeError(f"Decrypt/parse failed: {e}")

    def call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        mid = self._msg_id
        self._msg_id += 1
        req = {"id": mid, "method": method, "params": params}
        log_debug(self.debug, f"[{self.ip}] -> {req}")
        resp = self._send_recv(req)
        log_debug(self.debug, f"[{self.ip}] <- {resp}")
        return resp

    def info(self) -> Dict[str, Any]:
        # standard miIO.info call
        return self.call("miIO.info", [])

    def get_props(self, props: List[str]) -> Dict[str, Any]:
        # Most zhimi devices support get_prop with list of prop names.
        return self.call("get_prop", props)


# ------------------------- Domoticz Plugin -------------------------

class Plugin:
    STRIDE = 100  # unit spacing per device

    # local units
    U_POWER = 10
    U_MODE = 11
    U_AQI = 1
    U_FILTER_LIFE = 21
    U_FILTER_HOURS = 22

    def __init__(self):
        self.debug = False
        self.poll_seconds = 60
        self.next_poll = 0

        self.devices: Dict[int, MiioDevice] = {}  # pid -> device
        self.names: Dict[int, str] = {}           # pid -> name
        self.models: Dict[int, str] = {}          # pid -> model string

        self.q = queue.Queue()
        self.worker = threading.Thread(target=self._worker, name="XAPWorker", daemon=True)

    def _unit(self, pid: int, local: int) -> int:
        return (pid - 1) * self.STRIDE + local

    def _pid(self, unit: int) -> int:
        return (unit // self.STRIDE) + 1

    def _local(self, unit: int) -> int:
        return unit % self.STRIDE

    def onStart(self):
        if AES is None:
            Domoticz.Error("pycryptodome fehlt! Installiere: sudo python3.11 -m pip install -U pycryptodome")
            return

        self.debug = (Parameters["Mode6"] == "Debug")
        Domoticz.Debugging(1 if self.debug else 0)

        ips = split_csv(Parameters["Address"])
        toks = split_csv(Parameters["Mode1"])
        names = split_csv(Parameters.get("Mode2", ""))

        if len(ips) < 1 or len(ips) != len(toks):
            Domoticz.Error("IPs und Tokens müssen gleich viele sein (kommagetrennt). Beispiel: IP1,IP2 und TOKEN1,TOKEN2")
            return

        # poll interval
        try:
            self.poll_seconds = max(10, int(Parameters["Mode3"]) * 60)
        except Exception:
            self.poll_seconds = 60

        # init devices
        for idx, (ip, tok) in enumerate(zip(ips, toks), start=1):
            pid = idx
            name = names[idx - 1] if idx - 1 < len(names) else f"Air Purifier {pid}"
            self.names[pid] = name
            self.devices[pid] = MiioDevice(ip=ip, token_hex=tok, debug=self.debug, timeout=2.0)

        # Create Domoticz devices
        for pid in self.devices.keys():
            self._create_domoticz_devices(pid)

        self.worker.start()
        self.next_poll = 0
        Domoticz.Heartbeat(10)

        Domoticz.Log(f"Xiaomi Air Purifier Multi gestartet: {len(self.devices)} Geräte")

    def _create_domoticz_devices(self, pid: int):
        name = self.names[pid]

        # AQI
        u = self._unit(pid, self.U_AQI)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - AQI", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;AQI"}, Used=1).Create()

        # Power
        u = self._unit(pid, self.U_POWER)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Power", Unit=u, TypeName="Switch", Used=1).Create()

        # Mode selector
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

        # Filter life %
        u = self._unit(pid, self.U_FILTER_LIFE)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Filter %", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;%"}, Used=1).Create()

        # Filter hours used
        u = self._unit(pid, self.U_FILTER_HOURS)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Filter h", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;h"}, Used=1).Create()

    def onCommand(self, Unit, Command, Level, Hue):
        pid = self._pid(Unit)
        local = self._local(Unit)

        if pid not in self.devices:
            Domoticz.Error(f"Unbekanntes Gerät für Unit {Unit} (pid={pid})")
            return

        self.q.put(("cmd", pid, local, Command, Level))

    def onHeartbeat(self):
        self.q.put(("poll",))

    def _worker(self):
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

    def _poll_if_due(self):
        if now_ts() < self.next_poll:
            return
        self.next_poll = now_ts() + self.poll_seconds

        for pid, dev in self.devices.items():
            try:
                # Try to identify model once
                if pid not in self.models:
                    info = dev.info()
                    model = (info.get("result") or {}).get("model")
                    if isinstance(model, str):
                        self.models[pid] = model
                        Domoticz.Log(f"{self.names[pid]} Modell: {model}")

                # Read properties
                # Common for purifier 2/2S variants:
                # power, aqi, mode, filter1_life, filter1_hour_used
                resp = dev.get_props(["power", "aqi", "mode", "filter1_life", "filter1_hour_used"])
                result = resp.get("result", [])
                # result can be list in same order
                if isinstance(result, list) and len(result) >= 5:
                    power, aqi, mode, flife, fhours = result[0], result[1], result[2], result[3], result[4]
                else:
                    # fallback if dict-like
                    power = resp.get("power")
                    aqi = resp.get("aqi")
                    mode = resp.get("mode")
                    flife = resp.get("filter1_life")
                    fhours = resp.get("filter1_hour_used")

                # update AQI
                update_device(self._unit(pid, self.U_AQI), 0, str(aqi if aqi is not None else ""))

                # update power switch
                if str(power).lower() == "on":
                    update_device(self._unit(pid, self.U_POWER), 1, "On")
                elif str(power).lower() == "off":
                    update_device(self._unit(pid, self.U_POWER), 0, "Off")

                # update filter
                if flife is not None:
                    update_device(self._unit(pid, self.U_FILTER_LIFE), 0, str(flife))
                if fhours is not None:
                    update_device(self._unit(pid, self.U_FILTER_HOURS), 0, str(fhours))

                # update mode selector
                lvl = self._mode_to_level(mode)
                if lvl is not None:
                    update_device(self._unit(pid, self.U_MODE), 1, str(lvl))

            except Exception as e:
                Domoticz.Error(f"{self.names[pid]} Poll Fehler: {e}")

    def _mode_to_level(self, mode_val) -> Optional[int]:
        # MiIO often returns mode as string: "auto"/"silent"/"favorite"/"idle"
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

    def _handle_command(self, pid: int, local: int, command: str, level: int):
        dev = self.devices[pid]

        if local == self.U_POWER:
            want_on = str(command).strip().lower() == "on"
            dev.call("set_power", ["on" if want_on else "off"])
            # instant refresh
            self.next_poll = 0

        elif local == self.U_MODE:
            # selector gives 0/10/20/30
            try:
                lvl = int(level)
            except Exception:
                lvl = 30
            mode = self._level_to_mode(lvl)
            dev.call("set_mode", [mode])
            self.next_poll = 0

        else:
            log_debug(self.debug, f"Ignored command local={local} unit for pid={pid}")


# ------------------------- Domoticz hooks -------------------------

_plugin = Plugin()

def onStart():
    _plugin.onStart()

def onHeartbeat():
    _plugin.onHeartbeat()

def onCommand(Unit, Command, Level, Hue):
    _plugin.onCommand(Unit, Command, Level, Hue)
