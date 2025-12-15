# Xiaomi Air Purifier (Multi) – Domoticz Plugin (AirPurifier-plugin)

Ein Domoticz-Python-Plugin zur Steuerung von **mehreren** Xiaomi Luftreinigern (z.B. **Air Purifier 2** und **2S**) über das **MiIO UDP-Protokoll** (Port 54321).

✅ Multi-Device in **einer** Plugin-Instanz  
✅ **AQI** (Luftqualität)  
✅ **Filter %**  
✅ **Mode-Selector** (Idle/Silent/Favorite/Auto) – **Idle = AUS**  
✅ Optional: **Power-Switch**  
✅ Stabil: Timeout-Recovery, Pending-Fenster gegen “Zurückspringen”, Debounce gegen doppelte Commands  
✅ Kein `python-miio`, kein `cryptography` → keine PyO3/Subinterpreter-Probleme

---

## Voraussetzungen

- Domoticz (mit Python-Plugin-Unterstützung)
- Python 3
- Netzwerkzugriff vom Domoticz/Raspberry Pi auf die Luftreiniger (gleiches LAN/WLAN, kein Client-Isolation)

### Benötigte Pakete

#### Systempakete
```bash
sudo apt update
sudo apt install -y git python3 python3-pip

Python-Paket
Dieses Plugin nutzt pycryptodome (für AES):
sudo python3 -m pip install -U pycryptodome

Test (optional):

python3 -c "from Crypto.Cipher import AES; print('pycryptodome OK')"

In den Domoticz-Plugin-Ordner wechseln:

cd domoticz/plugins
git clone https://github.com/schurgan/AirPurifier-plugin.git

Rechte setzen (optional, aber oft hilfreich):

chmod -R 755 domoticz/plugins/AirPurifier-plugin

Domoticz neu starten:

sudo systemctl restart domoticz

Update (später)

cd domoticz/plugins/AirPurifier-plugin
git pull
sudo systemctl restart domoticz

Domoticz Hardware anlegen
Domoticz → Setup → Hardware → „Add“
Wähle das Plugin Xiaomi Air Purifier (Multi) aus und setze:

Parameter
IPs (comma separated)

Tokens (comma separated, 32 hex each)

Names (optional, comma separated)

Poll every X seconds
Empfehlung: 30 (Minimum im Plugin: 10)

Show Power Switch
Empfehlung: No (recommended) – weil der Mode-Selector bereits alles steuern kann.

Pending seconds (anti-bounce)
Empfehlung: 5
(Stabilisiert besonders beim 2S, damit der Selector nicht “zurückspringt”.)

Debug
Bei Problemen auf True stellen (liefert mehr Logs).

Bedienung in Domoticz
Pro Gerät werden normalerweise diese Geräte angelegt:

<Name> - AQI (Custom)

<Name> - Filter % (Custom)

<Name> - Mode (Selector Switch)

Idle = AUS

Silent / Favorite / Auto = EIN + Modus setzen

Optional (wenn aktiviert):

<Name> - Power (Switch)

Troubleshooting
“Handshake failed” / “timed out”
Token prüfen (32 hex Zeichen, korrektes Gerät)

IP prüfen (statisch oder per DHCP-Reservierung)

WLAN Router: AP/Client Isolation deaktivieren

Firewall/Filter: UDP Port 54321 muss erreichbar sein

Gerät und Domoticz müssen im selben Netz erreichbar sein

Selector springt zurück (v.a. 2S)
Pending-Logik ist bereits eingebaut.
Erhöhe im Hardware-Setup Pending seconds z.B. von 5 auf 7.

Domoticz startet Plugin nicht
Syntax prüfen:

python3 -m py_compile /home/schurgan/domoticz/plugins/AirPurifier-plugin/plugin.py

Prüfe, ob pycryptodome installiert ist:

python3 -c "from Crypto.Cipher import AES"

Sicherheit / Hinweis
Die MiIO Tokens sind geheim. Behandle sie wie Passwörter (nicht öffentlich posten).
