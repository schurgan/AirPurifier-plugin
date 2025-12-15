"""
<plugin key="XiaomiAirPurifierMulti" name="Xiaomi Air Purifier (Multi)" author="Alex" version="1.2.0">
    <description>
        Multi-device plugin for Xiaomi Air Purifier 2 / 2S using MiIO UDP protocol.
        No python-miio, no cryptography (avoids PyO3/subinterpreter issues). Uses pycryptodome.
        Features: AQI, Filter %, Mode selector (Idle=Off), optional Power switch.
        Stabilization: timeout auto-recovery, immediate feedback, pending window (prevents selector bouncing),
        debounce for duplicate mode commands (prevents On/Off/On in device logs).
    </description>
    <params>
        <param field="Address" label="IPs (comma separated)" width="300px" required="true" default="192.168.178.29,192.168.178.30"/>
        <param field="Mode1" label="Tokens (comma separated, 32 hex each)" width="420px" required="true" default="token1,token2"/>
        <param field="Mode2" label="Names (optional, comma separated)" width="300px" required="false" default="Air Purifier 2,Air Purifier 2S"/>
        <param field="Mode3" label="Poll every X seconds" width="80px" required="true" default="30"/>
        <param field="Mode4" label="Show Power Switch" width="160px">
            <options>
                <option label="No (recommended)" value="0" default="true"/>
                <option label="Yes" value="1"/>
            </options>
        </param>
        <param field="Mode5" label="Pending seconds (anti-bounce)" width="160px" required="true" default="5"/>
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

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception:
    AES = None
    pad = None
    unpad = None


# ---------------------------- Utils ----------------------------

def split_csv(v):
    return [x.strip() for x in (v or "").split(",") if x.strip()]

def md5(b):
    return hashlib.md5(b).digest()

def ts():
    return int(time.time())

def log_debug(enabled, msg):
    if enabled:
        Domoticz.Debug(msg)

def update_device(unit, n, s):
    if unit in Devices:
        if Devices[unit].nValue != n or Devices[unit].sValue != str(s):
            Devices[unit].Update(nValue=n, sValue=str(s))


# -------------------------- MiIO UDP --------------------------

class MiioDevice:
    """
    Minimal MiIO UDP implementation (AES-CBC with token-derived key/iv).
    Auto recovery: on timeout/error -> session reset -> re-handshake -> retry once.
    """

    def __init__(self, ip, token_hex, debug=False, timeout=4.0):
        self.ip = ip
        self.port = 54321
        self.debug = debug
        self.timeout = timeout

        token_hex = (token_hex or "").strip().lower()
        if len(token_hex) != 32:
            raise ValueError("Token must be 32 hex chars")

        self.token = bytes.fromhex(token_hex)
        self.key = md5(self.token)
        self.iv = md5(self.key + self.token)

        self.device_id = 0
        self.stamp = 0
        self.msg_id = 1

    def reset_session(self):
        self.device_id = 0
        self.stamp = 0

    def _sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        return s

    def handshake(self):
        # Classic MiIO hello: 21310020 + 28*FF
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

        magic, _length = struct.unpack_from(">HH", data, 0)
        if magic != 0x2131:
            return False

        self.device_id = struct.unpack_from(">I", data, 8)[0]
        self.stamp = struct.unpack_from(">I", data, 12)[0]
        log_debug(self.debug, f"[{self.ip}] Handshake OK device_id={self.device_id} stamp={self.stamp}")
        return True

    def _encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return cipher.encrypt(pad(plaintext, 16, style="pkcs7"))

    def _decrypt(self, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return unpad(cipher.decrypt(ciphertext), 16, style="pkcs7")

    def _checksum(self, header16, payload_enc):
        return hashlib.md5(header16 + self.token + payload_enc).digest()

    def _build_packet(self, payload_json):
        if self.device_id == 0:
            if not self.handshake():
                raise TimeoutError("Handshake failed")

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

    def _send_recv_once(self, payload_json):
        pkt = self._build_packet(payload_json)

        s = self._sock()
        try:
            s.sendto(pkt, (self.ip, self.port))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        if len(data) < 32:
            raise TimeoutError("Bad response length")

        payload_enc = data[32:]
        if not payload_enc:
            return {}

        payload_plain = self._decrypt(payload_enc)
        return json.loads(payload_plain.decode("utf-8", errors="replace"))

    def _send_recv(self, payload_json):
        last_err = None
        for _attempt in (1, 2):
            try:
                return self._send_recv_once(payload_json)
            except Exception as e:
                last_err = e
                self.reset_session()
                time.sleep(0.2)
        raise RuntimeError(str(last_err))

    def call(self, method, params):
        mid = self.msg_id
        self.msg_id += 1
        req = {"id": mid, "method": method, "params": params}
        log_debug(self.debug, f"[{self.ip}] -> {req}")
        resp = self._send_recv(req)
        log_debug(self.debug, f"[{self.ip}] <- {resp}")
        return resp

    def get_props(self, props):
        resp = self.call("get_prop", props)
        res = resp.get("result", [])
        return res if isinstance(res, list) else []

    def set_power(self, on):
        self.call("set_power", ["on" if on else "off"])

    def set_mode(self, mode):
        # mode: "auto"|"silent"|"favorite"
        self.call("set_mode", [mode])


# -------------------------- Domoticz Plugin --------------------------

class Plugin:
    STRIDE = 100  # unit spacing per device

    # local units
    U_AQI = 1
    U_POWER = 10
    U_MODE = 11
    U_FILTER_LIFE = 21

    def __init__(self):
        self.debug = False
        self.show_power = False

        self.poll_seconds = 30
        self.next_poll = 0

        self.pending_seconds = 5

        self.devices = {}  # pid -> MiioDevice
        self.names = {}    # pid -> name

        self.q = queue.Queue()
        self.worker = threading.Thread(target=self._worker, name="XAPWorker", daemon=True)

        # Pending state to prevent selector bouncing (esp. 2S)
        self.pending_until = {}  # pid -> unix time until we trust device again
        self.pending_level = {}  # pid -> selector level string ("0","10","20","30")

        # Debounce: ignore duplicate mode commands in short window
        self.last_mode_cmd_ts = {}      # pid -> timestamp
        self.last_mode_cmd_level = {}   # pid -> last level

        # Debounce power too (optional but helpful)
        self.last_power_cmd_ts = {}     # pid -> timestamp
        self.last_power_cmd_val = {}    # pid -> bool

    # unit mapping
    def _unit(self, pid, local):
        return (pid - 1) * self.STRIDE + local

    def _pid(self, unit):
        return (unit // self.STRIDE) + 1

    def _local(self, unit):
        return unit % self.STRIDE

    def onStart(self):
        if AES is None:
            Domoticz.Error("pycryptodome fehlt! Installiere: sudo python3 -m pip install -U pycryptodome")
            return

        self.debug = (Parameters["Mode6"] == "Debug")
        Domoticz.Debugging(1 if self.debug else 0)

        self.show_power = str(Parameters.get("Mode4", "0")).strip() == "1"

        try:
            self.poll_seconds = max(10, int(Parameters["Mode3"]))
        except Exception:
            self.poll_seconds = 30

        try:
            self.pending_seconds = max(2, int(Parameters.get("Mode5", "5")))
        except Exception:
            self.pending_seconds = 5

        ips = split_csv(Parameters["Address"])
        toks = split_csv(Parameters["Mode1"])
        names = split_csv(Parameters.get("Mode2", ""))

        if len(ips) < 1 or len(ips) != len(toks):
            Domoticz.Error("IPs und Tokens müssen gleich viele sein (kommagetrennt).")
            return

        self.devices.clear()
        self.names.clear()

        for idx, (ip, tok) in enumerate(zip(ips, toks), start=1):
            pid = idx
            name = names[pid - 1] if (pid - 1) < len(names) else f"Air Purifier {pid}"
            self.names[pid] = name
            self.devices[pid] = MiioDevice(ip=ip, token_hex=tok, debug=self.debug, timeout=4.0)

        for pid in self.devices.keys():
            self._ensure_domoticz_devices(pid)

        if not self.worker.is_alive():
            self.worker.start()

        self.next_poll = 0
        Domoticz.Heartbeat(10)
        Domoticz.Log(f"XiaomiAirPurifierMulti v1.2.0 gestartet: {len(self.devices)} Geräte")

        self.q.put(("poll_now",))

    def _ensure_domoticz_devices(self, pid):
        name = self.names[pid]

        # AQI
        u = self._unit(pid, self.U_AQI)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - AQI", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;AQI"}, Used=1).Create()

        # Mode selector (always)
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

        # Filter %
        u = self._unit(pid, self.U_FILTER_LIFE)
        if u not in Devices:
            Domoticz.Device(Name=f"{name} - Filter %", Unit=u, TypeName="Custom",
                            Options={"Custom": "1;%"}, Used=1).Create()

        # Optional Power switch
        u = self._unit(pid, self.U_POWER)
        if self.show_power:
            if u not in Devices:
                Domoticz.Device(Name=f"{name} - Power", Unit=u, TypeName="Switch", Used=1).Create()

    def onHeartbeat(self):
        self.q.put(("poll",))

    def onCommand(self, Unit, Command, Level, Hue):
        pid = self._pid(Unit)
        local = self._local(Unit)
        self.q.put(("cmd", pid, local, Command, Level))

    # ---------------- worker ----------------

    def _worker(self):
        while True:
            msg = self.q.get()
            try:
                kind = msg[0]
                if kind == "poll":
                    self._poll_if_due()
                elif kind == "poll_now":
                    self.next_poll = 0
                    self._poll_if_due(force=True)
                elif kind == "cmd":
                    _, pid, local, cmd, level = msg
                    self._handle_command(pid, local, cmd, level)
            except Exception as e:
                Domoticz.Error(f"Worker Fehler: {e}")
            finally:
                self.q.task_done()

    def _poll_if_due(self, force=False):
        if not force and ts() < self.next_poll:
            return
        self.next_poll = ts() + self.poll_seconds

        for pid, dev in self.devices.items():
            name = self.names.get(pid, f"Air Purifier {pid}")
            try:
                power, aqi, mode, flife = self._read_state(dev)

                # AQI
                if aqi is not None:
                    update_device(self._unit(pid, self.U_AQI), 0, str(aqi))

                # Filter %
                if flife is not None:
                    update_device(self._unit(pid, self.U_FILTER_LIFE), 0, str(flife))

                # Power string
                p = str(power).lower() if power is not None else ""

                # Power device (if shown)
                if self.show_power and (self._unit(pid, self.U_POWER) in Devices):
                    if p == "on":
                        update_device(self._unit(pid, self.U_POWER), 1, "On")
                    elif p == "off":
                        update_device(self._unit(pid, self.U_POWER), 0, "Off")

                # Mode selector stabilization:
                # OFF => always Idle (0).
                # During pending window keep requested selector level (prevents 2S bounce).
                now = ts()
                pend_until = self.pending_until.get(pid, 0)

                if p == "off":
                    update_device(self._unit(pid, self.U_MODE), 1, "0")
                else:
                    if now < pend_until:
                        req_lvl = self.pending_level.get(pid)
                        if req_lvl is not None:
                            update_device(self._unit(pid, self.U_MODE), 1, req_lvl)
                    else:
                        lvl2 = self._mode_to_level(mode)
                        if lvl2 is not None:
                            update_device(self._unit(pid, self.U_MODE), 1, str(lvl2))

            except Exception as e:
                Domoticz.Error(f"{name} Poll Fehler: {e}")

    def _read_state(self, dev):
        # Standard props for purifier 2/2S
        props = ["power", "aqi", "mode", "filter1_life"]
        res = dev.get_props(props)
        if len(res) >= 4:
            return res[0], res[1], res[2], res[3]
        raise RuntimeError(f"get_prop returned {res}")

    def _mode_to_level(self, mode_val):
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

    def _level_to_mode(self, level):
        if level == 10:
            return "silent"
        if level == 20:
            return "favorite"
        return "auto"

    def _handle_command(self, pid, local, command, level):
        if pid not in self.devices:
            return

        dev = self.devices[pid]
        name = self.names.get(pid, f"Air Purifier {pid}")

        # POWER switch (optional)
        if local == self.U_POWER:
            c = str(command).strip().lower()
            want_on = (c in ("on", "true", "1", "open", "start"))
            if c in ("off", "false", "0", "close", "stop"):
                want_on = False

            # Debounce power: ignore same request in 2 seconds
            now = ts()
            last_ts = self.last_power_cmd_ts.get(pid, 0)
            last_val = self.last_power_cmd_val.get(pid, None)
            if (last_val is not None) and (want_on == last_val) and ((now - last_ts) < 2):
                Domoticz.Log(f"{name} Power duplicate ignored (want_on={want_on})")
                return
            self.last_power_cmd_ts[pid] = now
            self.last_power_cmd_val[pid] = want_on

            Domoticz.Log(f"{name} Power command='{command}' -> want_on={want_on}")
            dev.set_power(want_on)

            # Pending protect (so poll doesn't immediately fight us)
            self.pending_until[pid] = ts() + self.pending_seconds
            self.pending_level[pid] = "0" if not want_on else self.pending_level.get(pid, "30")

            # Immediate UI feedback
            if self.show_power and (self._unit(pid, self.U_POWER) in Devices):
                update_device(self._unit(pid, self.U_POWER), 1 if want_on else 0, "On" if want_on else "Off")
            if not want_on:
                update_device(self._unit(pid, self.U_MODE), 1, "0")

            time.sleep(0.8)
            self.q.put(("poll_now",))
            return

        # MODE selector (always)
        if local == self.U_MODE:
            try:
                lvl = int(level)
            except Exception:
                lvl = 30

            # Debounce: same level within 2 seconds ignored
            now = ts()
            last_ts = self.last_mode_cmd_ts.get(pid, 0)
            last_lvl = self.last_mode_cmd_level.get(pid, -999)
            if lvl == last_lvl and (now - last_ts) < 2:
                Domoticz.Log(f"{name} Mode duplicate ignored (lvl={lvl})")
                return
            self.last_mode_cmd_ts[pid] = now
            self.last_mode_cmd_level[pid] = lvl

            # WICHTIG: Idle = AUS (niemals set_mode("idle"), sonst schaltet 2S ein!)
            if lvl == 0:
                Domoticz.Log(f"{name} Mode=Idle -> Power OFF")
                dev.set_power(False)

                # Immediate UI feedback
                update_device(self._unit(pid, self.U_MODE), 1, "0")
                if self.show_power and (self._unit(pid, self.U_POWER) in Devices):
                    update_device(self._unit(pid, self.U_POWER), 0, "Off")

                # Pending window: keep selector stable
                self.pending_until[pid] = ts() + self.pending_seconds
                self.pending_level[pid] = "0"

                time.sleep(0.8)
                self.q.put(("poll_now",))
                return

            # other modes => ON + set_mode
            self.pending_until[pid] = ts() + self.pending_seconds
            self.pending_level[pid] = str(lvl)

            mode = self._level_to_mode(lvl)
            Domoticz.Log(f"{name} Mode -> {mode} (Power ON)")
            dev.set_power(True)
            dev.set_mode(mode)

            update_device(self._unit(pid, self.U_MODE), 1, str(lvl))
            if self.show_power and (self._unit(pid, self.U_POWER) in Devices):
                update_device(self._unit(pid, self.U_POWER), 1, "On")

            time.sleep(0.8)
            self.q.put(("poll_now",))
            return


_plugin = Plugin()

def onStart():
    _plugin.onStart()

def onHeartbeat():
    _plugin.onHeartbeat()

def onCommand(Unit, Command, Level, Hue):
    _plugin.onCommand(Unit, Command, Level, Hue)
