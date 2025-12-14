# A Python plugin for Domoticz to access Xiaomi AirPurifier 2 / 2S
# Multi-device (2 devices) version based on original v0.2.3 logic
#
# - One Domoticz hardware instance controls 2 purifiers (Air Purifier 2 / 2S mix)
# - All original features preserved (AQI, avg AQI, pollution level alert, temperature, humidity,
#   motor speed, favorite level, power/mode/child lock/beep/LED, filter stats, illuminance)
# - Thread + Queue model preserved
#
# Config:
#   Address: "IP1,IP2"
#   Mode1:   "TOKEN1,TOKEN2"
#
# Notes:
# - Single plugin instance avoids the Domoticz subinterpreter issue that breaks PyO3 modules
#   when running multiple plugin instances.

"""
<plugin key="AirPurifier" name="AirPurifier" author="ManyAuthors+MultiPatch" version="0.3.0" wikilink="https://github.com/rytilahti/python-miio" externallink="https://github.com/kofec/domoticz-AirPurifier">
    <params>
        <param field="Address" label="IP Address (comma separated: IP1,IP2)" width="300px" required="true" default="127.0.0.1,127.0.0.2"/>
        <param field="Mode1" label="AirPurifier Token (comma separated: T1,T2)" default="" width="400px" required="true"  />
        <param field="Mode3" label="Check every x minutes" width="40px" default="15" required="true" />
        <param field="Mode6" label="Debug" width="75px">
            <options>
                <option label="True" value="Debug"/>
                <option label="False" value="Normal" default="true" />
            </options>
        </param>
    </params>
</plugin>
"""

import Domoticz
import sys
import datetime
import time
import threading
import queue
from queue import Empty

# -------- miio imports (keep backward compatibility logic) --------

def versiontuple(v):
    return tuple(map(int, (v.split("."))))

import miio

if versiontuple(miio.__version__) < versiontuple("0.5.12"):
    from miio.airpurifier import OperationMode, AirPurifierException, AirPurifier
else:
    from miio.integrations.airpurifier.zhimi.airpurifier import OperationMode, AirPurifierException, AirPurifier

# ---------------- Localization (kept as original) ----------------

L10N = {
    'pl': {
        "Air Quality Index": "Jakość powietrza",
        "Avarage Air Quality Index": "Średnia wartość AQI",
        "Air pollution Level": "Zanieczyszczenie powietrza",
        "Temperature": "Temperatura",
        "Humidity": "Wilgotność",
        "Fan Speed": "Prędkość wiatraka",
        "Favorite Fan Level": "Ulubiona prędkość wiatraka",
        "Sensor information": "Informacje o stacji",
        "Device Unit=%(Unit)d; Name='%(Name)s' already exists": "Urządzenie Unit=%(Unit)d; Name='%(Name)s' już istnieje",
        "Creating device Name=%(Name)s; Unit=%(Unit)d; ; TypeName=%(TypeName)s; Used=%(Used)d":
            "Tworzę urządzenie Name=%(Name)s; Unit=%(Unit)d; ; TypeName=%(TypeName)s; Used=%(Used)d",
        "Great air quality": "Bardzo dobra jakość powietrza",
        "Good air quality": "Dobra jakość powietrza",
        "Average air quality": "Przeciętna jakość powietrza",
        "Poor air quality": "Słaba jakość powietrza",
        "Bad air quality": "Zła jakość powietrza",
        "Really bad air quality": "Bardzo zła jakość powietrza",
        "Sensor id (%(sensor_id)d) not exists": "Sensor (%(sensor_id)d) nie istnieje",
        "Not authorized": "Brak autoryzacji",
        "Starting device update": "Rozpoczynanie aktualizacji urządzeń",
        "Update unit=%d; nValue=%d; sValue=%s": "Aktualizacja unit=%d; nValue=%d; sValue=%s",
        "Bad air today!": "Zła jakość powietrza",
        "Awaiting next pool: %s": "Oczekiwanie na następne pobranie: %s",
        "Next pool attempt at: %s": "Następna próba pobrania: %s",
        "Connection to airly api failed: %s": "Połączenie z airly api nie powiodło się: %s",
        "Unrecognized error: %s": "Nierozpoznany błąd: %s",
        "Filter life remaining": "Pozostała żywotność filtra",
        "Filter work hours": "Godziny pracy filtra",
        "Illuminance sensor": "Czujnik oświetlenia",
        "Child Lock": "Blokada dziecięca",
        "Beep": "Dźwięk",
    },
    'en': {}
}

def _(key):
    try:
        return L10N[Settings["Language"]][key]
    except Exception:
        return key

# ----------------- Helpers -----------------

def _split_csv(s: str):
    return [x.strip() for x in (s or "").split(",") if x.strip()]

def UpdateDevice(Unit, nValue, sValue):
    if Unit in Devices:
        if (Devices[Unit].nValue != nValue) or (Devices[Unit].sValue != str(sValue)):
            Devices[Unit].Update(nValue=nValue, sValue=str(sValue))
            Domoticz.Log("Update " + str(nValue) + ":'" + str(sValue) + "' (" + Devices[Unit].Name + ")")
    return


# ----------------- Exceptions (kept) -----------------

class UnauthorizedException(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

class SensorNotFoundException(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

class ConnectionErrorException(Exception):
    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


# ----------------- Plugin -----------------

class BasePlugin:
    enabled = False

    def __init__(self):
        self.device_names = {
        1: "Air Purifier 2",
        2: "Air Purifier 2S"
        }
        self.version = "0.3.0"

        # Multi-device: exactly 2 purifiers
        self.UNIT_STRIDE = 100  # units 1..99 for device1, 101..199 for device2
        self.purifiers = []     # [{"id":1,"ip":"...","token":"..."}, {"id":2,...}]
        self.MyAir = {}         # pid -> AirPurifier instance or None
        self.has_illuminance = {1: False, 2: False}

        self.debug = False
        self.inProgress = False

        # Original local UNIT constants (DO NOT CHANGE)
        self.UNIT_AIR_QUALITY_INDEX     = 1
        self.UNIT_AIR_POLLUTION_LEVEL   = 2
        self.UNIT_TEMPERATURE           = 3
        self.UNIT_HUMIDITY              = 4
        self.UNIT_MOTOR_SPEED           = 5
        self.UNIT_AVARAGE_AQI           = 6

        self.UNIT_POWER_CONTROL         = 10
        self.UNIT_MODE_CONTROL          = 11
        self.UNIT_MOTOR_SPEED_FAVORITE  = 12
        self.UNIT_CHILD_LOCK            = 13
        self.UNIT_BEEP                  = 15

        self.UNIT_LED                   = 20
        self.FILTER_WORK_HOURS          = 21
        self.FILTER_LIFE_REMAINING      = 22
        self.UNIT_ILLUMINANCE_SENSOR    = 23

        self.nextpoll = datetime.datetime.now()

        self.messageQueue = queue.Queue()
        self.messageThread = threading.Thread(
            name="QueueThreadPurifier",
            target=BasePlugin.handleMessage,
            args=(self,)
        )

    # ------- unit mapping (global <-> local+pid) -------

    def _offset(self, pid: int) -> int:
        return (pid - 1) * self.UNIT_STRIDE

    def _pid_from_unit(self, unit: int) -> int:
        return (unit // self.UNIT_STRIDE) + 1

    def _local_unit(self, unit: int) -> int:
        return unit % self.UNIT_STRIDE

    def _gunit(self, pid: int, local_unit: int) -> int:
        return self._offset(pid) + local_unit

    # ------- connection -------

    def connectIfNeeded(self, pid: int):
        """Ensure self.MyAir[pid] is connected."""
        for _ in range(1, 6):
            try:
                if self.MyAir.get(pid) is None:
                    p = next(x for x in self.purifiers if x["id"] == pid)
                    self.MyAir[pid] = AirPurifier(p["ip"], p["token"])
                break
            except AirPurifierException as e:
                Domoticz.Error(f"connectIfNeeded (purifier {pid}): " + str(e))
                self.MyAir[pid] = None

    def connectAllIfNeeded(self):
        for p in self.purifiers:
            self.connectIfNeeded(p["id"])

    # ------- worker thread -------

    def handleMessage(self):
        Domoticz.Debug("Entering message handler")
        while True:
            try:
                Message = self.messageQueue.get(block=True)
                if Message is None:
                    Domoticz.Debug("Exiting message handler")
                    self.messageQueue.task_done()
                    break

                if Message["Type"] == "onHeartbeat":
                    self.onHeartbeatInternal(Message["Fetch"])
                elif Message["Type"] == "onCommand":
                    # {Type,onCommand, Pid, Mthd, Arg}
                    self.onCommandInternal(Message["Pid"], Message["Mthd"], *Message["Arg"])

                self.messageQueue.task_done()

            except Exception as err:
                Domoticz.Error("handleMessage: " + str(err))
                # drop connections; will reconnect next run
                for p in self.purifiers:
                    self.MyAir[p["id"]] = None
                while not self.messageQueue.empty():
                    try:
                        self.messageQueue.get(False)
                    except Empty:
                        continue
                    self.messageQueue.task_done()

    # ------- variable templates (local units) -------

    def _variables_template(self):
        # Local units only; will be expanded to global units per purifier in onStart()
        return {
            self.FILTER_LIFE_REMAINING: {
                "Name":     _("Filter life remaining"),
                "TypeName": "Custom",
                "Options":  {"Custom": "1;%s" % "%"},
                "Image":    7,
                "Used":     1,
                "nValue":   0,
                "sValue":   None,
            },
            self.FILTER_WORK_HOURS: {
                "Name":     _("Filter work hours"),
                "TypeName": "Custom",
                "Options":  {"Custom": "1;%s" % "h"},
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   0,
            },
            self.UNIT_AIR_QUALITY_INDEX: {
                "Name":     _("Air Quality Index"),
                "TypeName": "Custom",
                "Options":  {"Custom": "1;%s" % "AQI"},
                "Image":    7,
                "Used":     1,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_AVARAGE_AQI: {
                "Name":     _("Avarage Air Quality Index"),
                "TypeName": "Custom",
                "Options":  {"Custom": "1;%s" % "AQI"},
                "Image":    7,
                "Used":     1,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_AIR_POLLUTION_LEVEL: {
                "Name":     _("Air pollution Level"),
                "TypeName": "Alert",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_TEMPERATURE: {
                "Name":     _("Temperature"),
                "TypeName": "Temperature",
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_HUMIDITY: {
                "Name":     _("Humidity"),
                "TypeName": "Humidity",
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_MOTOR_SPEED: {
                "Name":     _("Fan Speed"),
                "TypeName": "Custom",
                "Options":  {"Custom": "1;%s" % "RPM"},
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_CHILD_LOCK: {
                "Name":     _("Child Lock"),
                "TypeName": "Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_BEEP: {
                "Name":     _("Beep"),
                "TypeName": "Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            # LED & controls are created manually (as in original) but we also keep them in doUpdate logic
            self.UNIT_LED: {
                "Name":     "Fan LED",
                "TypeName": "Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_POWER_CONTROL: {
                "Name":     "Power",
                "TypeName": "Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
            },
            self.UNIT_MODE_CONTROL: {
                "Name":     "Mode",
                "TypeName": "Selector Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
                "Options":  {
                    "LevelActions": "||||",
                    "LevelNames": "Idle|Silent|Favorite|Auto",
                    "LevelOffHidden": "false",
                    "SelectorStyle": "0"
                }
            },
            self.UNIT_MOTOR_SPEED_FAVORITE: {
                "Name":     _("Favorite Fan Level"),
                "TypeName": "Selector Switch",
                "Image":    7,
                "Used":     0,
                "nValue":   0,
                "sValue":   None,
                "Options":  {
                    "LevelActions": "|||||||||||||||||",
                    "LevelNames": "1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17",
                    "LevelOffHidden": "false",
                    "SelectorStyle": "0"
                }
            },
        }

    # ------- device creation (extended to support Type/Subtype devices) -------

    def createDevice(self, unit=None):
        """Create Domoticz virtual device(s) for a given global unit or all."""
        def createSingleDevice(gunit):
            item = self.variables[gunit]
            _unit = gunit
            _name = item['Name']

            if gunit in Devices:
                Domoticz.Debug(_("Device Unit=%(Unit)d; Name='%(Name)s' already exists") % {'Unit': gunit, 'Name': _name})
                return

            _options = item.get('Options', {})
            _typename = item.get('TypeName', None)
            _used = item.get('Used', 0)
            _image = item.get('Image', 0)

            # Some devices (like illuminance in original) used Type/Subtype/Switchtype.
            _type = item.get('Type', None)
            _subtype = item.get('Subtype', None)
            _switchtype = item.get('Switchtype', None)

            Domoticz.Debug(_("Creating device Name=%(Name)s; Unit=%(Unit)d; ; TypeName=%(TypeName)s; Used=%(Used)d") % {
                'Name': _name, 'Unit': _unit, 'TypeName': (_typename if _typename else "n/a"), 'Used': _used,
            })

            if _typename:
                Domoticz.Device(Name=_name, Unit=_unit, TypeName=_typename, Image=_image, Options=_options, Used=_used).Create()
            elif _type is not None and _subtype is not None:
                Domoticz.Device(Name=_name, Unit=_unit, Type=_type, Subtype=_subtype, Switchtype=_switchtype, Image=_image, Options=_options, Used=_used).Create()
            else:
                # fallback - should not happen
                Domoticz.Device(Name=_name, Unit=_unit, TypeName="Custom", Used=_used, Options=_options, Image=_image).Create()

        if unit is not None:
            if unit in self.variables:
                createSingleDevice(unit)
        else:
            for k in list(self.variables.keys()):
                createSingleDevice(k)

    # ------- start/stop -------

    def onStart(self):
        Domoticz.Debug("onStart called")
        if Parameters["Mode6"] == 'Debug':
            self.debug = True
            Domoticz.Debugging(1)
            DumpConfigToLog()
        else:
            Domoticz.Debugging(0)

        ips = _split_csv(Parameters.get("Address", ""))
        toks = _split_csv(Parameters.get("Mode1", ""))

        if len(ips) != 2 or len(toks) != 2:
            Domoticz.Error("Bitte genau 2 IPs und 2 Tokens angeben (kommasepariert): Address=IP1,IP2 und Mode1=TOKEN1,TOKEN2")
            return

        self.purifiers = [
            {"id": 1, "ip": ips[0], "token": toks[0]},
            {"id": 2, "ip": ips[1], "token": toks[1]},
        ]
        self.MyAir = {1: None, 2: None}
        self.has_illuminance = {1: False, 2: False}

        # Connect to both devices once
        self.connectAllIfNeeded()
        for pid in (1, 2):
            if self.MyAir.get(pid) is not None:
                self.MyAir[pid]._timeout = 1

        self.messageThread.start()

        Domoticz.Heartbeat(20)
        self.pollinterval = int(Parameters["Mode3"]) * 60

        # Detect illuminance availability per device, log status (as original)
        for pid in (1, 2):
            try:
                self.connectIfNeeded(pid)
                if self.MyAir.get(pid) is None:
                    continue
                res = self.MyAir[pid].status()
                Domoticz.Log(f"Purifier {pid} status: {res}")
                self.has_illuminance[pid] = (getattr(res, "illuminance", None) is not None)
            except Exception as e:
                Domoticz.Error(f"Purifier {pid} initial status failed: {e}")
                self.MyAir[pid] = None

        # Build variables dict for BOTH purifiers (global units)
        tmpl = self._variables_template()
        self.variables = {}

        for pid in (1, 2):
            off = self._offset(pid)
            for local_unit, meta in tmpl.items():
                gunit = off + local_unit
                item = dict(meta)  # copy
                # prefix name to distinguish
                item["Name"] = f"{self.device_names.get(pid, f'Air Purifier {pid}')} - {item['Name']}"
                self.variables[gunit] = item

            # Add illuminance only if supported, exactly like original style
            if self.has_illuminance[pid]:
                g = off + self.UNIT_ILLUMINANCE_SENSOR
                self.variables[g] = {
                    "Name": f"{self.device_names.get(pid, f'Air Purifier {pid}')} - " + _("Illuminance sensor"),
                    # Use Type/Subtype like original manual creation
                    "Type":     244,
                    "Subtype":  73,
                    "Switchtype": 7,
                    "Image":    7,
                    "Used":     1,
                    "nValue":   0,
                    "sValue":   None,
                    "Options":  {"Custom": "1;%s" % "lux"},
                }

        # Create selector/switch devices proactively (like original did for some)
        # (createDevice will also create on first update, but we keep explicit behavior)
        self.createDevice()  # create all defined devices now

        self.onHeartbeat(fetch=False)

    def onStop(self):
        Domoticz.Log("onStop called")

        while not self.messageQueue.empty():
            try:
                self.messageQueue.get(False)
            except Empty:
                continue
            self.messageQueue.task_done()

        self.messageQueue.put(None)
        Domoticz.Log("Clearing message queue ...")
        self.messageQueue.join()

        Domoticz.Log("Threads still active: " + str(threading.active_count()) + ", should be 1.")
        while threading.active_count() > 1:
            for thread in threading.enumerate():
                if thread.name != threading.current_thread().name:
                    Domoticz.Log("'" + thread.name + "' is still running, waiting otherwise Domoticz will abort on plugin exit.")
            time.sleep(1.0)

        Domoticz.Debugging(0)

    # ------- unused hooks kept -------

    def onConnect(self, Status, Description):
        Domoticz.Log("onConnect called")

    def onMessage(self, Data, Status, Extra):
        Domoticz.Log("onMessage called")

    def onNotification(self, Name, Subject, Text, Status, Priority, Sound, ImageFile):
        Domoticz.Log("Notification: " + Name + "," + Subject + "," + Text + "," + Status + "," + str(Priority) + "," + Sound + "," + ImageFile)

    def onDisconnect(self):
        Domoticz.Log("onDisconnect called")

    # ------- command handling -------

    def onCommandInternal(self, pid, func, *arg):
        try:
            stat = func(*arg)
            Domoticz.Log(f"Purifier {pid} cmd result: {stat}")
            # Fetch status right after command
            self.onHeartbeat(fetch=True)
        except AirPurifierException as e:
            try:
                Domoticz.Log("Something fail: " + e.output.decode())
            except Exception:
                Domoticz.Log("Something fail: " + str(e))
            self.onHeartbeat(fetch=False)
        except Exception as e:
            Domoticz.Error(_("Unrecognized command error: %s") % str(e))

    def UpdateLedStatus(self, pid, enabled):
        unit = self._gunit(pid, self.UNIT_LED)
        if enabled:
            UpdateDevice(unit, 1, "Fan LED ON")
        else:
            UpdateDevice(unit, 0, "Fan LED OFF")

    def onCommand(self, Unit, Command, Level, Hue):
        Domoticz.Log("onCommand called for Unit " + str(Unit) + ": Parameter '" + str(Command) + "', Level: " + str(Level))

        pid = self._pid_from_unit(Unit)
        local = self._local_unit(Unit)

        if pid not in (1, 2):
            Domoticz.Error(f"Unknown purifier id calculated from Unit={Unit}: pid={pid}")
            return

        self.connectIfNeeded(pid)
        dev = self.MyAir.get(pid)
        if dev is None:
            Domoticz.Error(f"Purifier {pid} not connected, command ignored.")
            return

        mthd = None
        arg = []

        if local == self.UNIT_POWER_CONTROL:
            mthd = dev.on if str(Command).upper() == "ON" else dev.off

        elif local == self.UNIT_MODE_CONTROL and int(Level) == 0:
            mthd = dev.set_mode
            arg = [OperationMode.Idle]
        elif local == self.UNIT_MODE_CONTROL and int(Level) == 10:
            mthd = dev.set_mode
            arg = [OperationMode.Silent]
        elif local == self.UNIT_MODE_CONTROL and int(Level) == 20:
            mthd = dev.set_mode
            arg = [OperationMode.Favorite]
        elif local == self.UNIT_MODE_CONTROL and int(Level) == 30:
            mthd = dev.set_mode
            arg = [OperationMode.Auto]

        elif local == self.UNIT_MOTOR_SPEED_FAVORITE:
            mthd = dev.set_favorite_level
            arg = [int(int(Level) / 10 + 1)]

        elif local == self.UNIT_CHILD_LOCK:
            mthd = dev.set_child_lock
            arg = [True if str(Command).upper() in ("TRUE", "ON") else False]

        elif local == self.UNIT_BEEP:
            mthd = dev.set_volume
            arg = [50 if str(Command).upper() in ("TRUE", "ON") else 0]

        elif local == self.UNIT_LED:
            enabled = str(Command).upper() == "ON"
            mthd = dev.set_led
            arg = [enabled]
            self.UpdateLedStatus(pid, enabled)

        else:
            Domoticz.Log("onCommand: unit not handled")
            return

        Domoticz.Log(str({"Type": "onCommand", "Pid": pid, "Mthd": mthd, "Arg": arg}))
        self.messageQueue.put({"Type": "onCommand", "Pid": pid, "Mthd": mthd, "Arg": arg})

    # ------- polling/heartbeat -------

    def postponeNextPool(self, seconds=3600):
        self.nextpoll = (datetime.datetime.now() + datetime.timedelta(seconds=seconds))
        return self.nextpoll

    def onHeartbeat(self, fetch=False):
        Domoticz.Debug("onHeartbeat called")
        self.messageQueue.put({"Type": "onHeartbeat", "Fetch": fetch})
        return True

    def onHeartbeatInternal(self, fetch=False):
        now = datetime.datetime.now()
        if fetch is False:
            if now < self.nextpoll:
                Domoticz.Debug(_("Awaiting next pool: %s") % str(self.nextpoll))
                return

        self.postponeNextPool(seconds=self.pollinterval)

        # poll both devices
        self.connectAllIfNeeded()

        for pid in (1, 2):
            dev = self.MyAir.get(pid)
            if dev is None:
                continue

            off = self._offset(pid)

            try:
                res = dev.status()
                Domoticz.Log(f"Purifier {pid}: {res}")

                # Mode selector
                try:
                    if str(res.mode) == "OperationMode.Idle":
                        UpdateDevice(off + self.UNIT_MODE_CONTROL, 0, '0')
                    elif str(res.mode) == "OperationMode.Silent":
                        UpdateDevice(off + self.UNIT_MODE_CONTROL, 10, '10')
                    elif str(res.mode) == "OperationMode.Favorite":
                        UpdateDevice(off + self.UNIT_MODE_CONTROL, 20, '20')
                    elif str(res.mode) == "OperationMode.Auto":
                        UpdateDevice(off + self.UNIT_MODE_CONTROL, 30, '30')
                    else:
                        Domoticz.Log("Wrong state for UNIT_MODE_CONTROL: " + str(res.mode))
                except Exception:
                    pass

                # Favorite level selector
                try:
                    UpdateDevice(off + self.UNIT_MOTOR_SPEED_FAVORITE, 1, str(int(int(res.favorite_level) - 1) * 10))
                except Exception:
                    pass

                # Average AQI
                try:
                    self.variables[off + self.UNIT_AVARAGE_AQI]['sValue'] = str(res.average_aqi)
                except Exception:
                    pass

                # AQI
                try:
                    self.variables[off + self.UNIT_AIR_QUALITY_INDEX]['sValue'] = str(res.aqi)
                except Exception:
                    pass

                # Temperature
                try:
                    self.variables[off + self.UNIT_TEMPERATURE]['sValue'] = str(res.temperature)
                except Exception:
                    pass

                # Motor speed
                try:
                    self.variables[off + self.UNIT_MOTOR_SPEED]['sValue'] = str(res.motor_speed)
                except Exception:
                    pass

                # Power
                try:
                    if str(res.power) == "on":
                        UpdateDevice(off + self.UNIT_POWER_CONTROL, 1, "AirPurifier ON")
                    elif str(res.power) == "off":
                        UpdateDevice(off + self.UNIT_POWER_CONTROL, 0, "AirPurifier OFF")
                except Exception:
                    pass

                # Pollution level alert from AQI (original thresholds)
                try:
                    aqi_val = int(res.aqi)
                    if aqi_val < 50:
                        pollutionLevel = 1
                        pollutionText = _("Great air quality")
                    elif aqi_val < 100:
                        pollutionLevel = 1
                        pollutionText = _("Good air quality")
                    elif aqi_val < 150:
                        pollutionLevel = 2
                        pollutionText = _("Average air quality")
                    elif aqi_val < 200:
                        pollutionLevel = 3
                        pollutionText = _("Poor air quality")
                    elif aqi_val < 300:
                        pollutionLevel = 4
                        pollutionText = _("Bad air quality")
                    else:
                        pollutionLevel = 4
                        pollutionText = _("Really bad air quality")

                    self.variables[off + self.UNIT_AIR_POLLUTION_LEVEL]['nValue'] = pollutionLevel
                    self.variables[off + self.UNIT_AIR_POLLUTION_LEVEL]['sValue'] = pollutionText
                except Exception:
                    pass

                # Humidity (original status mapping)
                try:
                    humidity = int(round(res.humidity))
                    if humidity < 40:
                        humidity_status = 2
                    elif 40 <= humidity <= 60:
                        humidity_status = 0
                    elif 40 < humidity <= 70:
                        humidity_status = 1
                    else:
                        humidity_status = 3

                    self.variables[off + self.UNIT_HUMIDITY]['nValue'] = humidity
                    self.variables[off + self.UNIT_HUMIDITY]['sValue'] = str(humidity_status)
                except Exception:
                    pass

                # Filter stats
                try:
                    self.variables[off + self.FILTER_WORK_HOURS]['nValue'] = res.filter_hours_used
                    self.variables[off + self.FILTER_WORK_HOURS]['sValue'] = str(res.filter_hours_used)
                except Exception:
                    pass

                try:
                    self.variables[off + self.FILTER_LIFE_REMAINING]['nValue'] = res.filter_life_remaining
                    self.variables[off + self.FILTER_LIFE_REMAINING]['sValue'] = str(res.filter_life_remaining)
                except Exception:
                    pass

                # Illuminance (only if supported and created)
                try:
                    if self.has_illuminance.get(pid, False):
                        g = off + self.UNIT_ILLUMINANCE_SENSOR
                        if g in self.variables:
                            self.variables[g]['nValue'] = res.illuminance
                            self.variables[g]['sValue'] = str(res.illuminance)
                except Exception:
                    pass

                # Update LED status
                try:
                    self.UpdateLedStatus(pid, bool(res.led))
                except Exception:
                    pass

                # Child lock switch
                try:
                    if res.child_lock:
                        UpdateDevice(off + self.UNIT_CHILD_LOCK, 1, "ChildLock ON")
                    else:
                        UpdateDevice(off + self.UNIT_CHILD_LOCK, 0, "ChildLock OFF")
                except Exception:
                    pass

                # Beep switch from volume
                try:
                    if res.volume is not None and res.volume > 0:
                        UpdateDevice(off + self.UNIT_BEEP, 1, "Beep ON")
                    else:
                        UpdateDevice(off + self.UNIT_BEEP, 0, "Beep OFF")
                except Exception:
                    pass

            except AirPurifierException as e:
                Domoticz.Error(f"onHeartbeatInternal purifier {pid}: " + str(e))
                self.MyAir[pid] = None
            except Exception as e:
                Domoticz.Error(_("Unrecognized heartbeat error: %s") % str(e))
                self.MyAir[pid] = None

        # Push updates for all devices/units (original behavior)
        self.doUpdate()

        if Parameters["Mode6"] == 'Debug':
            Domoticz.Debug("onHeartbeat finished")

    def doUpdate(self):
        Domoticz.Log(_("Starting device update"))
        for unit in self.variables:
            Domoticz.Debug(str(self.variables[unit]))
            nV = self.variables[unit].get('nValue', 0)
            sV = self.variables[unit].get('sValue', None)

            # cast float to str with one decimal, replace '.'->',' (as original)
            if isinstance(sV, float):
                sV = str(float("{0:.1f}".format(sV))).replace('.', ',')

            # Create device if required
            if sV is not None and sV != "":
                self.createDevice(unit=unit)
                if unit in Devices:
                    Domoticz.Log(_("Update unit=%d; nValue=%d; sValue=%s") % (unit, nV, sV))
                    Devices[unit].Update(nValue=nV, sValue=str(sV))


# ----------------- global hooks -----------------

global _plugin
_plugin = BasePlugin()

def onStart():
    global _plugin
    _plugin.onStart()

def onStop():
    global _plugin
    _plugin.onStop()

def onConnect(Status, Description):
    global _plugin
    _plugin.onConnect(Status, Description)

def onMessage(Data, Status, Extra):
    global _plugin
    _plugin.onMessage(Data, Status, Extra)

def onCommand(Unit, Command, Level, Hue):
    global _plugin
    _plugin.onCommand(Unit, Command, Level, Hue)

def onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile):
    global _plugin
    _plugin.onNotification(Name, Subject, Text, Status, Priority, Sound, ImageFile)

def onDisconnect():
    global _plugin
    _plugin.onDisconnect()

def onHeartbeat():
    global _plugin
    _plugin.onHeartbeat()

# ----------------- Debug helper (original) -----------------

def DumpConfigToLog():
    for x in Parameters:
        if Parameters[x] != "":
            Domoticz.Debug("'" + x + "':'" + str(Parameters[x]) + "'")
    Domoticz.Debug("Device count: " + str(len(Devices)))
    for x in Devices:
        Domoticz.Debug("Device:           " + str(x) + " - " + str(Devices[x]))
        Domoticz.Debug("Device ID:       '" + str(Devices[x].ID) + "'")
        Domoticz.Debug("Device Name:     '" + Devices[x].Name + "'")
        Domoticz.Debug("Device nValue:    " + str(Devices[x].nValue))
        Domoticz.Debug("Device sValue:   '" + Devices[x].sValue + "'")
        Domoticz.Debug("Device LastLevel: " + str(Devices[x].LastLevel))
    return
