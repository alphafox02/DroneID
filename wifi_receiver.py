#!/usr/bin/env python3
# (c) 2024 B.Kerler
import os
import sys
import time
from subprocess import Popen, PIPE, STDOUT
import argparse
import json
from pathlib import Path
import socket as pysock
from threading import Thread, Event

from Library.utils import (
    search_interfaces,
    get_iw_interfaces,
    extract_wifi_if_details,
    enable_monitor_mode,
    set_interface_channel,
    cexec,
    enable_managed_mode,
)
from OpenDroneID.wifi_parser import oui_to_parser
from scapy.all import *
from scapy.layers.dot11 import Dot11EltVendorSpecific, Dot11, Dot11Elt, Dot11Action
import zmq

verbose = False
context = zmq.Context()
socket = None


def _have_raw_caps() -> bool:
    """Return True if current process can open an AF_PACKET raw socket."""
    try:
        s = pysock.socket(pysock.AF_PACKET, pysock.SOCK_RAW, 0)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return True


def _list_wireless_ifaces() -> list[str]:
    sys_class = Path("/sys/class/net")
    if not sys_class.exists():
        return []
    out = []
    for ifdir in sys_class.iterdir():
        ifname = ifdir.name
        if ifname == "lo":
            continue
        if (ifdir / "wireless").exists():
            out.append(ifname)
    return out


def _first_usb_wifi_iface() -> str | None:
    """
    Minimal, robust heuristic:
      - Prefer wireless ifaces whose names start with 'wl' AND len(name) > 6
        (e.g., 'wlx9cefd5feec' typical for USB/udev MAC naming)
      - Within those, prefer names starting with 'wlx'
      - If none, and exactly one wireless iface exists, pick it
      - Else return None to trigger the existing interactive picker
    """
    wl_ifaces = _list_wireless_ifaces()
    long_wl = [i for i in wl_ifaces if i.startswith("wl") and len(i) > 6]

    if long_wl:
        wlx_first = sorted([i for i in long_wl if i.startswith("wlx")])
        if wlx_first:
            return wlx_first[0]
        return sorted(long_wl)[0]

    if len(wl_ifaces) == 1:
        return wl_ifaces[0]

    return None


def channel_hopper(
    interface: str,
    primary_channel: int,
    secondary_channel: int,
    primary_dwell: float,
    secondary_dwell: float,
    stop_evt: Event,
):
    while not stop_evt.is_set():
        set_interface_channel(interface, primary_channel)
        end = time.time() + primary_dwell
        while time.time() < end and not stop_evt.is_set():
            time.sleep(0.1)

        set_interface_channel(interface, secondary_channel)
        end = time.time() + secondary_dwell
        while time.time() < end and not stop_evt.is_set():
            time.sleep(0.1)


# -------------------------------------------------------------
# Frame subtype notes (restored original comments)
#
# subtype 0 = Management
# subtype 0x8 = Beacon
# subtype 0x13 = Action
#
# NAN Service Discovery Frames are encoded in 0x13 and may contain DRI Info
# NAN Synchronization Beacon is encoded in 0x8 but doesn't contain DRI Info
# Broadcast Message can only happen on channel 6 and contains DRI Info
#
# With ASTM added:
# - ASTM Wi-Fi RID also uses Action frames (subtype 0x13), but category 127
# -------------------------------------------------------------


# -----------------------------
# NEW: ASTM Vendor Action Frame parser (Real Wi-Fi RID)
# -----------------------------
def parse_astm_vendor_action(packet):
    global socket, verbose

    if not packet.haslayer(Dot11Action):
        return

    action = packet[Dot11Action]

    # Vendor-specific Action Frame (REAL ASTM Wi-Fi RID)
    if action.category != 127:
        return

    raw = bytes(action)
    if len(raw) < 6:
        return

    oui_bytes = raw[2:5]
    if oui_bytes != b"\xFA\x0B\xBC":
        return

    vend_type = raw[5]
    if vend_type != 0x0D:
        return

    payload = bytes([vend_type]) + raw[6:]
    mac = packet.addr2

    parser = oui_to_parser(int.from_bytes(oui_bytes, "big"), payload)
    if parser is None:
        return

    msg = parser.msg.get("DRI") or parser.msg.get("Beacon")
    if not msg:
        return

    out = {"DroneID": {mac: msg}}

    if socket:
        socket.send_string(json.dumps(out))
    if verbose:
        print(json.dumps(out))


# -----------------------------
# EXISTING NAN Action Frame parser (unchanged)
# BUT NAN-only frames no longer go to ZMQ (Option C)
# -----------------------------
def parse_nan_action_frame(packet):
    global socket, verbose

    if not packet.haslayer(Dot11Action):
        return

    raw = bytes(packet[Dot11Action])
    if len(raw) < 7:
        return

    # NAN specific
    if raw[0] != 0x04 or raw[1] != 0x09:
        return

    oui_bytes = raw[2:5]
    if oui_bytes != b"\xFA\x0B\xBC":
        return

    vend_type = raw[5]
    vendor_payload = bytes([vend_type]) + raw[6:]
    mac = packet.addr2

    parser = oui_to_parser(int.from_bytes(oui_bytes, "big"), vendor_payload)
    if parser is None:
        return

    msg = parser.msg.get("DRI") or parser.msg.get("Beacon")

    # NAN with NO RID present → suppress from ZMQ (but show in verbose)
    if msg is None:
        if verbose:
            print(f"[NAN] {mac} (no RID payload)")
        return

    # NAN that DOES contain RID → forward (Option C)
    out = {"DroneID": {mac: msg}}

    if socket:
        socket.send_string(json.dumps(out))
    if verbose:
        print(json.dumps(out))


def pcapng_parser(filename: str):
    while True:
        for packet in PcapReader(filename):
            try:
                filter_frames(packet)
            except Exception:
                pass
            except KeyboardInterrupt:
                break


def filter_frames(packet: Packet) -> None:
    global socket
    global verbose

    macdb = {}
    pt = packet.getlayer(Dot11)

    # Action Frames (NAN + ASTM)
    if pt is not None and pt.subtype == 0x13:
        parse_astm_vendor_action(packet)
        parse_nan_action_frame(packet)

    # Existing Vendor-Specific IE path (DJI legacy, Skydio legacy)
    if pt is not None and pt.subtype in [0, 0x8, 0x13]:
        if packet.haslayer(Dot11EltVendorSpecific):
            vendor_spec = packet.getlayer(Dot11EltVendorSpecific)
            mac = packet.payload.addr2
            macdb["DroneID"] = {}
            macdb["DroneID"][mac] = []
            while vendor_spec:
                parser = oui_to_parser(vendor_spec.oui, vendor_spec.info)
                if parser is not None:
                    if "DRI" in parser.msg:
                        macdb["DroneID"][mac] = parser.msg["DRI"]
                    elif "Beacon" in parser.msg:
                        macdb["DroneID"][mac] = parser.msg["Beacon"]

                    if socket:
                        socket.send_string(json.dumps(macdb))
                    if verbose or not socket:
                        print(json.dumps(macdb))

                break


def main():
    global verbose
    global socket
    info = "Host-side receiver for OpenDrone ID wifi (c) B.Kerler 2024-2025"
    print(info)
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable zmq")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4223", help="Define zmq server settings")
    aparse.add_argument("--interface", help="Define zmq host")
    aparse.add_argument("--pcap", help="Use pcap file")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print messages")
    aparse.add_argument("-g", action="store_true", help="Use 5Ghz channel 149")
    aparse.add_argument(
        "--hop",
        action="store_true",
        help="Hop between 2.4 GHz (ch 6) and 5 GHz (ch 149)",
    )
    aparse.add_argument(
        "--hop-cycle",
        default="3,1",
        help="Dwell times in seconds for 2.4 GHz and 5 GHz when --hop is set (default: 3,1)",
    )
    args = aparse.parse_args()

    if os.geteuid() != 0 and not _have_raw_caps():
        print("Missing CAP_NET_RAW/CAP_NET_ADMIN.\n")
        exit(1)

    interfaces = search_interfaces()
    if args.verbose:
        verbose = True

    if args.interface is None and args.pcap is None:
        interface = _first_usb_wifi_iface()
        if interface is None:
            interface = get_iw_interfaces(interfaces)
    elif args.interface is not None:
        interface = args.interface
    elif args.pcap is not None:
        interface = None
    else:
        print("--pcap [file.pcapng] or --interface [wifi_monitor_interface] needed")
        exit(1)

    if verbose:
        print(f"[auto] selected interface: {interface}")

    hop_thread = None
    hop_stop_evt = None

    if args.hop:
        channel = 6
    elif args.g:
        channel = 149
    else:
        channel = 6

    if interface is not None:
        i2d = extract_wifi_if_details(interface)
        if not enable_monitor_mode(i2d, interface):
            sys.stdout.flush()
            exit(1)
        print(f"Setting wifi channel {channel}")
        set_interface_channel(interface, channel)

        if args.hop:
            try:
                primary_dwell, secondary_dwell = map(float, args.hop_cycle.split(","))
            except ValueError:
                print("Invalid --hop-cycle format, expected 'primary,secondary'")
                sys.exit(1)

            print(
                f"Channel hopping enabled: ch 6 ({primary_dwell}s) <-> ch 149 ({secondary_dwell}s)"
            )
            hop_stop_evt = Event()
            hop_thread = Thread(
                target=channel_hopper,
                args=(
                    interface,
                    6,
                    149,
                    primary_dwell,
                    secondary_dwell,
                    hop_stop_evt,
                ),
                daemon=True,
                name="chan_hopper",
            )
            hop_thread.start()

    #
    # -----------------
    # ZMQ BLOCK PRESERVED EXACTLY
    # -----------------
    #
    if args.zmq:
        socket = context.socket(zmq.XPUB)
        socket.setsockopt(zmq.XPUB_VERBOSE, True)

        url = f"tcp://{args.zmqsetting}"
        socket.bind(url)

        def log(*msg):
            s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("%s:" % s, *msg, end="\n", file=sys.stderr)

        def zmq_thread(sock):
            try:
                while True:
                    event = sock.recv()
                    if event[0] == 1:
                        log("new subscriber for", event[1:])
                    elif event[0] == 0:
                        log("unsubscribed", event[1:])
            except zmq.error.ContextTerminated:
                pass

        zthread = Thread(target=zmq_thread, args=[socket], daemon=True, name="zmq")
        zthread.start()

    if interface is not None:
        sniffer = AsyncSniffer(
            iface=interface, lfilter=lambda s: s.haslayer(Dot11), prn=filter_frames
        )
        sniffer.start()
        print(f"Starting sniffer on interface {interface}")
        try:
            while True:
                sniffer.join()
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        print(f"Stopping sniffer on interface {interface}")
        sniffer.stop()

        if hop_thread is not None and hop_stop_evt is not None:
            hop_stop_evt.set()
            hop_thread.join(timeout=2)

        if interface is not None:
            i2d = extract_wifi_if_details(interface)
            enable_managed_mode(i2d, interface)
    else:
        pcapng_parser(args.pcap)


if __name__ == "__main__":
    main()

