#!/usr/bin/env python
import argparse
import socket

from credagent import contact_agent


def main(command=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--socket_address', required=True)
    parser.add_argument('--name', required=True)
    args = parser.parse_args(command)

    socket.setdefaulttimeout(60)
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(args.socket_address)

    result = contact_agent(sock, args.name)
    print(result)


if __name__ == '__main__':
    main()
