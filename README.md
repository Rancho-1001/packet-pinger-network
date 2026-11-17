# Packet-Level Pinger

A from-scratch ICMP pinger in pure Python (standard library only). It
constructs echo-request packets byte-by-byte — type, code, RFC 1071
checksum, identifier, sequence number, and an embedded send timestamp —
and sends them over a raw socket. No `ping` subprocess, no third-party
libraries: the packet format is the project.

## Features

- **Ping mode:** per-reply RTT lines plus a statistics summary
  (packets transmitted/received, % loss, min/avg/max/stddev RTT)
- **Traceroute mode:** TTL increments with ICMP Time Exceeded parsing
  (including extracting the original identifier/sequence from the
  quoted packet inside the error message)
- **UDP mode:** an unprivileged fallback that runs the same
  RTT/loss statistics over timestamped UDP echo probes, with a tiny
  built-in echo server for testing

## Usage

```bash
# ICMP ping (needs elevated privileges for raw sockets)
sudo python3 src/pinger.py 127.0.0.1 -c 5
sudo python3 src/pinger.py example.com -c 10 -i 0.5

# Traceroute
sudo python3 src/pinger.py 1.1.1.1 --traceroute --max-hops 20

# UDP fallback (no privileges needed): start the echo server, then probe it
python3 src/pinger.py --serve
python3 src/pinger.py 127.0.0.1 --udp -c 5
```

On macOS, raw sockets require `sudo`. On Linux, `sudo` works too, or
grant the interpreter `CAP_NET_RAW`.

## What is verified

- The checksum implementation passes the RFC 1071 worked example
  (bytes `00 01 f2 03 f4 f5 f6 f7` → checksum `0x220d`)
- A built echo request verifies against its own checksum
- The reply parser correctly extracts type/identifier/sequence from a
  synthetic echo-reply packet

## Design notes

- The send timestamp is embedded in the payload (bytes 0–7), so RTT can
  be measured from the reply alone.
- Replies are matched on identifier + sequence, so unrelated ICMP
  traffic on the raw socket is ignored.
- Statistics use population standard deviation, matching the summary
  format of the system `ping`.
