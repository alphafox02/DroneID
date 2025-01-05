#!/usr/bin/env python3
"""
dji_receiver.py

Connects to AntSDR, receives DJI DroneID data, converts to ZMQ-compatible JSON format,
and publishes it via an efficient ZMQ XPUB socket.
"""

import socket
import struct
import json
import logging
import zmq
import time

# Hardcoded configuration
ANTSDR_IP = "192.168.1.10"
ANTSDR_PORT = 41030
ZMQ_PUB_IP = "0.0.0.0"
ZMQ_PUB_PORT = 4221  # Port to serve DJI receiver data

def setup_logging(debug: bool = True):
    """Configure logging to console."""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )

def iso_timestamp_now() -> str:
    """Return current UTC time as an ISO8601 string with 'Z' suffix."""
    return time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())

def parse_frame(frame: bytes):
    """Parses the raw frame from AntSDR."""
    try:
        package_type = frame[2]
        package_length = struct.unpack('<H', frame[3:5])[0]
        data = frame[5:5 + package_length - 5]
        return package_type, data
    except struct.error:
        logging.error("Failed to parse frame.")
        return None, None

def parse_data_1(data: bytes) -> dict:
    """Parses data of package type 0x01."""
    try:
        serial_number = data[:64].decode('utf-8').rstrip('\x00')
        device_type = data[64:128].decode('utf-8').rstrip('\x00')
        app_lat = struct.unpack('<d', data[129:137])[0]  # Pilot app latitude (home point)
        app_lon = struct.unpack('<d', data[137:145])[0]  # Pilot app longitude (home point)
        drone_lat = struct.unpack('<d', data[145:153])[0]  # Drone latitude
        drone_lon = struct.unpack('<d', data[153:161])[0]  # Drone longitude
        height_agl = struct.unpack('<d', data[161:169])[0]  # Height above ground level
        geodetic_altitude = struct.unpack('<d', data[169:177])[0]  # Altitude (MSL)
        speed_e = struct.unpack('<d', data[201:209])[0]  # Speed east (m/s)
        speed_n = struct.unpack('<d', data[209:217])[0]  # Speed north (m/s)
        speed_u = struct.unpack('<d', data[217:225])[0]  # Vertical speed (up, m/s)
        rssi = struct.unpack('<h', data[225:227])[0]

        horizontal_speed = (speed_e**2 + speed_n**2)**0.5

        return {
            "serial_number": serial_number,
            "device_type": device_type,
            "app_lat": app_lat,
            "app_lon": app_lon,
            "drone_lat": drone_lat,
            "drone_lon": drone_lon,
            "height_agl": height_agl,
            "geodetic_altitude": geodetic_altitude,
            "horizontal_speed": horizontal_speed,
            "vertical_speed": speed_u,
            "rssi": rssi
        }
    except (UnicodeDecodeError, struct.error) as e:
        logging.error(f"Error parsing data: {e}")
        return {}

def format_as_zmq_json(parsed_data: dict) -> list:
    """Formats the parsed AntSDR data into a ZMQ-compatible JSON structure."""
    if not parsed_data:
        return []

    message_list = []

    # Basic ID Message
    basic_id_message = {
        "Basic ID": {
            "id_type": "Serial Number (ANSI/CTA-2063-A)",
            "id": parsed_data.get("serial_number", "unknown"),
            "description": parsed_data.get("device_type", "DJI Drone")
        }
    }
    message_list.append(basic_id_message)

    # Location/Vector Message
    location_vector_message = {
        "Location/Vector Message": {
            "latitude": parsed_data["drone_lat"],
            "longitude": parsed_data["drone_lon"],
            "geodetic_altitude": parsed_data["geodetic_altitude"],
            "height_agl": parsed_data["height_agl"],
            "speed": parsed_data["horizontal_speed"],
            "vert_speed": parsed_data["vertical_speed"]
        }
    }
    message_list.append(location_vector_message)

    # Self-ID Message
    self_id_message = {
        "Self-ID Message": {
            "text": parsed_data.get("device_type", "DJI Drone")
        }
    }
    message_list.append(self_id_message)

    # System Message (pilot location if valid)
    if is_valid_latlon(parsed_data["app_lat"], parsed_data["app_lon"]):
        system_message = {
            "System Message": {
                "latitude": parsed_data["app_lat"],
                "longitude": parsed_data["app_lon"]
            }
        }
        message_list.append(system_message)

    return message_list

def is_valid_latlon(lat: float, lon: float) -> bool:
    """Check if latitude and longitude are within valid ranges."""
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and lat != 0.0 and lon != 0.0

def send_zmq_message(zmq_pub_socket: zmq.Socket, message_list: list):
    """Send the ZMQ JSON-formatted message."""
    try:
        json_message = json.dumps(message_list)
        zmq_pub_socket.send_string(json_message)
        logging.debug(f"Sent JSON via ZMQ: {json_message}")
    except Exception as e:
        logging.error(f"Failed to send JSON via ZMQ: {e}")

def tcp_client():
    """Connects to AntSDR and publishes messages via ZMQ XPUB."""
    context = zmq.Context()
    zmq_pub_socket = context.socket(zmq.XPUB)  # XPUB to support efficient subscriptions
    zmq_pub_socket.bind(f"tcp://{ZMQ_PUB_IP}:{ZMQ_PUB_PORT}")
    logging.info(f"ZMQ XPUB socket bound to tcp://{ZMQ_PUB_IP}:{ZMQ_PUB_PORT}")

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((ANTSDR_IP, ANTSDR_PORT))
                logging.info(f"Connected to AntSDR at {ANTSDR_IP}:{ANTSDR_PORT}")

                while True:
                    frame = client_socket.recv(1024)
                    if not frame:
                        logging.warning("Connection closed by AntSDR.")
                        break

                    package_type, data = parse_frame(frame)
                    if package_type == 0x01 and data:
                        parsed_data = parse_data_1(data)
                        zmq_message_list = format_as_zmq_json(parsed_data)
                        if zmq_message_list:
                            send_zmq_message(zmq_pub_socket, zmq_message_list)

        except (ConnectionRefusedError, socket.error) as e:
            logging.error(f"Connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            continue
        except Exception as e:
            logging.error(f"Unexpected error: {e}. Retrying in 5 seconds...")
            time.sleep(5)
            continue

def main():
    setup_logging()
    tcp_client()

if __name__ == "__main__":
    main()