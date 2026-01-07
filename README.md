# UDP Traceroute in Python

This is a custom implementation of the traceroute utility using Python's raw sockets. It sends UDP probes with increasing TTL values and listens for ICMP "Time Exceeded" messages to map the route to a destination.

## Features
- Uses `SOCK_RAW` to capture ICMP replies.
- Sends UDP packets to high ports (33434+).
- Automatically detects local IP for binding.
- Decodes ICMP headers to validate the original packet.

## Prerequisites
- Python 3.x
- **Administrator / Root privileges** are required to create raw sockets.

## Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/USERNAME/udp-traceroute-python.git](https://github.com/USERNAME/udp-traceroute-python.git)
