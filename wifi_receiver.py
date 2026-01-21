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

from Library.utils import search_interfaces, get_iw_interfaces, extract_wifi_if_details, enable_monitor_mode, \
    set_interface_channel, cexec, enable_managed_mode
from OpenDroneID.wifi_parser import oui_to_parser
from scapy.all import *
from scapy.layers.dot11 import Dot11EltVendorSpecific, Dot11, Dot11Elt
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
        # Treat other errors as non-fatal for this probe.
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

def channel_hopper(interface: str, channels: tuple[int, int], dwell_times: tuple[float, float], stop_evt: Event):
    """
    Bounce between two channels until stop_evt is set.
    channels: (first_channel, second_channel)
    dwell_times: seconds to stay on each channel in the same order.
    """
    idx = 0
    while not stop_evt.is_set():
        channel = channels[idx]
        dwell = dwell_times[idx]
        set_interface_channel(interface, channel)
        end = time.time() + dwell
        while time.time() < end and not stop_evt.is_set():
            time.sleep(0.1)
        idx = (idx + 1) % 2

def pcapng_parser(filename: str):
    while True:
        for packet in PcapReader(filename):
            try:
                filter_frames(packet)
            except Exception as err:
                pass
            except KeyboardInterrupt:
                break

def filter_frames(packet: Packet) -> None:
    global socket
    global verbose
    macdb = {}
    pt = packet.getlayer(Dot11)
    # subtype 0 = Management, 0x8 = Beacon, 0x13 = Action
    # NAN Service Discovery Frames shall be encoded in 0x13 and contain DRI Info
    # NAN Synchronization Beacon shall be encoded in 0x8 but doesn't contain DRI Info
    # Broadcast Message can only happen on channel 6 and contains DRI Info
    if pt is not None and pt.subtype in [0, 0x8, 0x13]:
        if packet.haslayer(Dot11EltVendorSpecific):  # check vendor specific ID -> 221
            vendor_spec: Dot11EltVendorSpecific = packet.getlayer(Dot11EltVendorSpecific)
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
                    if not socket or verbose:
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
    aparse.add_argument(
        "-g",
        action="store_true",
        help="Use 5GHz channel 149 (enables 2.4/5GHz hopping unless --no-hop)",
    )
    aparse.add_argument(
        "--no-hop",
        action="store_true",
        help="When -g is set, stay on 5GHz only (disable 5G/2.4GHz hopping)",
    )
    aparse.add_argument(
        "--hop-cycle",
        default="3,1",
        help="Dwell times in seconds for 2.4GHz and 5GHz when hopping (format: twofour,five) [default: 3,1]",
    )
    args = aparse.parse_args()

    # Runtime capability check (works with systemd AmbientCapabilities or setcap)
    if os.geteuid() != 0 and not _have_raw_caps():
        print(
            "Missing CAP_NET_RAW/CAP_NET_ADMIN. Either:\n"
            f"  sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' {sys.executable}\n"
            "or run via systemd with AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN.\n"
        )
        exit(1)

    interfaces = search_interfaces()
    if args.verbose:
        verbose = True

    if args.interface is None and args.pcap is None:
        # Prefer a long-named wl* (typically USB) iface; else fall back to existing selection
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
    hop_enabled = args.g and not args.no_hop
    # When hopping, start on 2.4GHz to favor capture there; otherwise honor -g.
    if hop_enabled:
        channel = 6
    else:
        channel = 149 if args.g else 6

    if interface is not None:
        i2d = extract_wifi_if_details(interface)
        if not enable_monitor_mode(i2d, interface):
            sys.stdout.flush()
            exit(1)
        print(f"Setting wifi channel {channel}")
        set_interface_channel(interface, channel)

        if hop_enabled:
            try:
                dwell_24g, dwell_5g = map(float, args.hop_cycle.split(","))
            except ValueError:
                print("Invalid --hop-cycle format, expected 'twofour,five' (e.g. 3,1)")
                sys.exit(1)

            print(
                f"Channel hopping enabled: ch 6 ({dwell_24g}s) <-> ch 149 ({dwell_5g}s)"
            )
            hop_stop_evt = Event()
            hop_thread = Thread(
                target=channel_hopper,  # 2.4 first, then 5
                args=(interface, (6, 149), (dwell_24g, dwell_5g), hop_stop_evt),
                daemon=True,
                name="chan_hopper",
            )
            hop_thread.start()

    zthread = None
    if args.zmq:
        socket = context.socket(zmq.XPUB)
        socket.setsockopt(zmq.XPUB_VERBOSE, True)
        url = f"tcp://{args.zmqsetting}"
        socket.setsockopt(zmq.XPUB_VERBOSE, True)
        socket.bind(url)

        def zmq_thread(socket):
            try:
                while True:
                    event = socket.recv()
                    # Event is one byte 0=unsub or 1=sub, followed by topic
                    if event[0] == 1:
                        log("new subscriber for", event[1:])
                    elif event[0] == 0:
                        log("unsubscribed", event[1:])
            except zmq.error.ContextTerminated:
                pass

        def log(*msg):
            s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("%s:" % s, *msg, end="\n", file=sys.stderr)

        zthread = Thread(target=zmq_thread, args=[socket], daemon=True, name='zmq')
        zthread.start()

    if interface is not None:
        sniffer = AsyncSniffer(
            iface=interface,
            lfilter=lambda s: s.haslayer(Dot11) and s.getlayer(Dot11).subtype == 0x8,
            prn=filter_frames,
            store=False,  # Don't store packets in memory - prevents memory leak
        )
        sniffer.start()
        print(f"Starting sniffer on interface {interface}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        print(f"Stopping sniffer on interface {interface}")
        sniffer.stop()
        if hop_thread is not None and hop_stop_evt is not None:
            hop_stop_evt.set()
            hop_thread.join(timeout=2)
        if args.zmq:
            zthread.join()
        if interface is not None:
            i2d = extract_wifi_if_details(interface)
            enable_managed_mode(i2d, interface)
    else:
        pcapng_parser(args.pcap)

if __name__ == "__main__":
    main()
