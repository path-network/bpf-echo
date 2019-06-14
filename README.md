# eBPF Echo Server

bpf-echo is a blazing fast TCP & UDP echo server that supports IPv4 and IPv6 traffic.
Its implementation leverages [extended Berkeley Packet Filter](https://lwn.net/Articles/740157/) and [BPF Compiler Collection](https://github.com/iovisor/bcc) in order to redirect outgoing packets straight back to the sending socket's receive queue.
It's perfect for benchmarking proxy servers, or network libraries, where you want to make sure that the upstream server is not a bottleneck.

## Requirements

The requirements for running `bpf-echo` are:

- Python 3
- pyroute2: `pip3 install pyroute2`
- BPF Compiler Collection Python 3 libraries.
  It's included in many distributions, e.g. as `python3-bpfcc` in Ubuntu package repositories.
  Check out [bcc's INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for more details
- new enough Linux kernel - at least version `4.1`
- root access - required for loading eBPF classifier.

## Example

```
$ sudo ./bpf-echo --ipv4 127.0.0.1 --port 1122 # run in different terminal
$ echo "hello" | nc -W1 127.0.0.1 1122
hello
```

## Usage

```
usage: bpf-echo.py [-h] [--ipv4 IPV4] [--ipv6 IPV6] [--port PORT]
                   [--ifname IFNAME]

optional arguments:
  -h, --help       show this help message and exit
  --ipv4 IPV4      IPv4 address that will reflect packets. Disabled if empty
                   string. (default: 127.0.0.1)
  --ipv6 IPV6      IPv6 address that will reflect packets. Disabled if empty
                   string. (default: )
  --port PORT      TCP/UDP destination port that will reflect packets.
                   (default: 12345)
  --ifname IFNAME  Interface the eBPF classifier will be loaded on. (default:
                   lo)
```

## Caveats

The BPF implementation is rather simple, and thus it makes some compromises:

- it doesn't handle TCP three-way handshake by itself, instead passing any packets with SYN, FIN or RST flags to an actual socket that's initialized in the Python code
- otherwise, it reflects TCP and UDP packets _as is_, not touching anything else than IP addresses and ports
- it doesn't support 802.1Q headers, IPv4 options or IPv6 extension headers
- it has to be loaded on a loopback interface.
  The reflecting IP addresses don't have to be local - as long as you set up routing rules that will route those packets to loopback.
