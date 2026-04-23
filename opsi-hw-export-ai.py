#!/usr/bin/env python3
"""
Generiert via Claude
OPSI Hardware Inventory Export
Exportiert CPU, RAM, Festplatte, MAC-Adressen, OS und letzte Aktivität
als CSV-Datei über die OPSI JSON-RPC API.

Verwendung:
    python opsi_export.py --host https://opsi-server:4447 --user admin --password SECRET
    python opsi_export.py --host https://opsi-server:4447 --user admin --password SECRET --output export.csv
"""

import argparse
import csv
import json
import sys
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT = "opsi_export.csv"

CSV_COLUMNS = [
    "Client",
    "CPU",
    "RAM_GB",
    "Festplatte_GB",
    "Festplatten_Typ",
    "MAC_LAN",
    "MAC_WLAN",
    "Betriebssystem",
    "Letzte_Aktivitaet",
]

# ---------------------------------------------------------------------------
# OPSI JSON-RPC Hilfsfunktionen
# ---------------------------------------------------------------------------

def build_rpc_payload(method: str, params: list) -> bytes:
    payload = {
        "id": 1,
        "method": method,
        "params": params,
    }
    return json.dumps(payload).encode("utf-8")


def rpc_call(base_url: str, user: str, password: str, method: str, params: list,
             verify_ssl: bool = True) -> dict:
    """Führt einen OPSI JSON-RPC-Aufruf durch und gibt das result-Feld zurück."""
    url = f"{base_url.rstrip('/')}/rpc"
    data = build_rpc_payload(method, params)

    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[FEHLER] HTTP {e.code} bei {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"[FEHLER] Verbindung fehlgeschlagen: {e.reason}", file=sys.stderr)
        sys.exit(1)

    if body.get("error"):
        print(f"[FEHLER] RPC-Fehler: {body['error']}", file=sys.stderr)
        sys.exit(1)

    return body.get("result", [])

# ---------------------------------------------------------------------------
# Datenabfragen
# ---------------------------------------------------------------------------

def get_all_clients(base_url, user, password, verify_ssl):
    """Gibt eine Liste aller Client-IDs zurück."""
    result = rpc_call(base_url, user, password,
                      "host_getObjects",
                      [[], {"type": "OpsiClient"}],
                      verify_ssl)
    return [h["id"] for h in result]


def get_hardware_info(base_url, user, password, clients, verify_ssl):
    """
    Ruft Hardware-Audit-Daten für alle Clients ab.
    Gibt ein dict {client_id: [hardware_objects]} zurück.
    """
    # Alle Hardware-Objekte auf einmal abrufen (effizienter als Einzelabfragen)
    result = rpc_call(base_url, user, password,
                      "auditHardwareOnHost_getObjects",
                      [[]],
                      verify_ssl)

    data = {}
    for obj in result:
        cid = obj.get("hostId") or obj.get("clientId", "")
        if cid not in data:
            data[cid] = []
        data[cid].append(obj)
    return data


def get_last_seen(base_url, user, password, verify_ssl):
    """Gibt ein dict {client_id: last_seen_str} zurück."""
    result = rpc_call(base_url, user, password,
                      "host_getObjects",
                      [["id", "lastSeen"], {"type": "OpsiClient"}],
                      verify_ssl)
    return {h["id"]: h.get("lastSeen", "") for h in result}


def get_installed_os(base_url, user, password, verify_ssl):
    """
    Versucht das installierte OS aus dem Software-Audit zu lesen.
    Gibt ein dict {client_id: os_string} zurück.
    """
    try:
        result = rpc_call(base_url, user, password,
                          "auditSoftwareOnClient_getObjects",
                          [["clientId", "name", "version"],
                           {"name": ["Microsoft Windows*", "Windows*", "Ubuntu*",
                                     "Debian*", "Linux*"]}],
                          verify_ssl)
    except SystemExit:
        return {}

    os_map = {}
    for obj in result:
        cid = obj.get("clientId", "")
        if cid and cid not in os_map:
            os_map[cid] = f"{obj.get('name', '')} {obj.get('version', '')}".strip()
    return os_map

# ---------------------------------------------------------------------------
# Hardware-Parser
# ---------------------------------------------------------------------------

def bytes_to_gb(value) -> str:
    """Konvertiert Bytes (int oder str) in GB, gerundet auf 1 Dezimalstelle."""
    try:
        gb = int(value) / (1024 ** 3)
        return f"{gb:.1f}"
    except (TypeError, ValueError):
        return ""


def mb_to_gb(value) -> str:
    """Konvertiert MB in GB."""
    try:
        gb = int(value) / 1024
        return f"{gb:.1f}"
    except (TypeError, ValueError):
        return ""


def parse_cpu(hw_objects: list) -> str:
    # PROCESSOR zuerst – enthält den echten CPU-Namen
    for obj in hw_objects:
        if obj.get("hardwareClass", "").upper() in ("PROCESSOR", "CPU"):
            name = obj.get("name", "") or obj.get("description", "")
            if name:
                return name
    # COMPUTER_SYSTEM nur als Fallback (name = Hostname, daher unerwünscht)
    for obj in hw_objects:
        if obj.get("hardwareClass", "").upper() == "COMPUTER_SYSTEM":
            model = obj.get("model", "")
            if model:
                return model
    return ""


def parse_ram(hw_objects: list) -> str:
    """Summiert alle RAM-Module (capacity = Bytes) und gibt den Wert in GB zurück."""
    total_bytes = 0
    found = False

    for obj in hw_objects:
        cls = obj.get("hardwareClass", "").upper()
        if cls == "MEMORY_MODULE":
            cap = obj.get("capacity") or obj.get("size")
            try:
                total_bytes += int(cap)   # OPSI liefert stets Bytes
                found = True
            except (TypeError, ValueError):
                pass

    if not found:
        # Fallback: totalPhysicalMemory aus COMPUTER_SYSTEM (ebenfalls Bytes)
        for obj in hw_objects:
            if obj.get("hardwareClass", "").upper() == "COMPUTER_SYSTEM":
                mem = obj.get("totalPhysicalMemory")
                try:
                    total_bytes = int(mem)
                    found = True
                    break
                except (TypeError, ValueError):
                    pass

    if total_bytes:
        gb = total_bytes / (1024 ** 3)
        return f"{gb:.1f}"
    return ""


def parse_disk(hw_objects: list) -> tuple:
    """
    Gibt (kapazitaet_gb, typ) der ersten Festplatte mit gültigem size-Wert zurück.
    Typ: NVMe, SSD oder HDD — ermittelt aus description/model/name.
    """
    for obj in hw_objects:
        cls = obj.get("hardwareClass", "").upper()
        if cls not in ("HARDDISK_DRIVE", "DISK_DRIVE", "HARDDISK", "PHYSICALDISK"):
            continue

        size_raw = obj.get("size") or obj.get("diskSize") or obj.get("capacity")
        try:
            size_bytes = int(size_raw)
            if size_bytes <= 0:
                continue
        except (TypeError, ValueError):
            continue  # size null/leer → überspringen

        # Typ ermitteln: description, model und name auswerten
        desc  = (obj.get("description") or "").upper()
        model = (obj.get("model")       or "").upper()
        name  = (obj.get("name")        or "").upper()
        combined = f"{desc} {model} {name}"

        if "NVME" in combined:
            disk_type = "NVMe"
        elif "SSD" in combined or "SOLID" in combined:
            disk_type = "SSD"
        else:
            disk_type = "HDD"

        gb = size_bytes / (1024 ** 3)
        return f"{gb:.0f}", disk_type

    return "", ""


def parse_mac_addresses(hw_objects: list) -> tuple:
    """
    Gibt (mac_lan, mac_wlan) zurück.
    Unterscheidet per Beschreibung / Name ob LAN oder WLAN.
    """
    mac_lan = ""
    mac_wlan = ""

    for obj in hw_objects:
        cls = obj.get("hardwareClass", "").upper()
        if cls not in ("NETWORK_CONTROLLER", "NETWORK_ADAPTER",
                       "BASE_BOARD", "NETWORKADAPTER"):
            continue

        mac = obj.get("macAddress", "") or obj.get("mac", "")
        if not mac or mac.upper() in ("", "00:00:00:00:00:00",
                                      "FF:FF:FF:FF:FF:FF"):
            continue

        desc = (obj.get("description") or obj.get("name") or
                obj.get("productName") or "").upper()

        if any(kw in desc for kw in ("WIRELESS", "WIFI", "WI-FI", "WLAN",
                                     "802.11", "WLAN", "AX", "AC")):
            if not mac_wlan:
                mac_wlan = mac
        else:
            if not mac_lan:
                mac_lan = mac

    return mac_lan, mac_wlan

# ---------------------------------------------------------------------------
# OS aus Produkten ermitteln (Fallback)
# ---------------------------------------------------------------------------

def get_os_from_products(base_url, user, password, verify_ssl):
    """
    Liest installierte OPSI-Produkte und leitet daraus das OS ab.
    Gibt dict {client_id: os_string} zurück.
    """
    try:
        result = rpc_call(base_url, user, password,
                          "productOnClient_getObjects",
                          [["clientId", "productId", "productVersion"],
                           {"installationStatus": "installed",
                            "productId": ["windows10", "windows11",
                                          "ubuntu", "debian", "win*"]}],
                          verify_ssl)
    except SystemExit:
        return {}

    os_map = {}
    for obj in result:
        cid = obj.get("clientId", "")
        if cid and cid not in os_map:
            pid = obj.get("productId", "")
            ver = obj.get("productVersion", "")
            os_map[cid] = f"{pid} {ver}".strip()
    return os_map


def format_last_seen(raw: str) -> str:
    """Formatiert den OPSI-Timestamp in lesbares Datum/Uhrzeit."""
    if not raw:
        return ""
    try:
        # OPSI liefert typischerweise 'YYYY-MM-DD HH:MM:SS'
        dt = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return raw

# ---------------------------------------------------------------------------
# Hauptprogramm
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OPSI Hardware Inventory → CSV Export",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--host", required=True,
                        help="OPSI Server URL, z.B. https://opsi-server:4447")
    parser.add_argument("--user", required=True,
                        help="OPSI Benutzername")
    parser.add_argument("--password", required=True,
                        help="OPSI Passwort")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"Ausgabedatei (Standard: {DEFAULT_OUTPUT})")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="SSL-Zertifikat nicht prüfen (selbstsignierte Zerts)")
    parser.add_argument("--clients", nargs="*",
                        help="Nur bestimmte Clients exportieren (optional)")
    args = parser.parse_args()

    verify_ssl = not args.no_verify_ssl

    print(f"[INFO] Verbinde mit {args.host} ...")

    # Clients laden
    if args.clients:
        clients = args.clients
        print(f"[INFO] {len(clients)} Clients manuell angegeben.")
    else:
        clients = get_all_clients(args.host, args.user, args.password, verify_ssl)
        print(f"[INFO] {len(clients)} Clients gefunden.")

    if not clients:
        print("[WARNUNG] Keine Clients gefunden. Export abgebrochen.")
        sys.exit(0)

    # Hardware-Daten abrufen
    print("[INFO] Lade Hardware-Inventar ...")
    hw_data = get_hardware_info(args.host, args.user, args.password,
                                clients, verify_ssl)

    # Letzte Aktivität
    print("[INFO] Lade Aktivitätsdaten ...")
    last_seen = get_last_seen(args.host, args.user, args.password, verify_ssl)

    # OS ermitteln
    print("[INFO] Lade Betriebssystem-Informationen ...")
    os_map = get_installed_os(args.host, args.user, args.password, verify_ssl)

    # CSV schreiben
    print(f"[INFO] Schreibe CSV nach '{args.output}' ...")
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, delimiter=";")
        writer.writeheader()

        for client_id in sorted(clients):
            hw_objects = hw_data.get(client_id, [])

            cpu = parse_cpu(hw_objects)
            ram = parse_ram(hw_objects)
            disk_gb, disk_type = parse_disk(hw_objects)
            mac_lan, mac_wlan = parse_mac_addresses(hw_objects)
            os_name = os_map.get(client_id, "")
            last_activity = format_last_seen(last_seen.get(client_id, ""))

            writer.writerow({
                "Client":           client_id,
                "CPU":              cpu,
                "RAM_GB":           ram,
                "Festplatte_GB":    disk_gb,
                "Festplatten_Typ":  disk_type,
                "MAC_LAN":          mac_lan,
                "MAC_WLAN":         mac_wlan,
                "Betriebssystem":   os_name,
                "Letzte_Aktivitaet": last_activity,
            })

    print(f"[OK] Export abgeschlossen: {len(clients)} Clients in '{args.output}'")


if __name__ == "__main__":
    main()
