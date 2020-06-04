#!/usr/bin/pyton3

import sys
import argparse
from plumbum.cmd import sudo, wg

class Config:
    def __init__(self):
        super().__init__()


def parse_cmd_line() -> Config:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    # generate client
    gen_client_parser = subparsers.add_parser("gen_client", help="generate a client profile")
    gen_client_parser.set_defaults(which="gen_client")
    gen_client_parser.add_argument("--client_virt_ip", required=True)
    gen_client_parser.add_argument("--client_listen_port", required=True)
    gen_client_parser.add_argument("--server_config", required=True)
    gen_client_parser.add_argument("--routed_nets", default="0.0.0.0/0")
    gen_client_parser.add_argument("--persistent_keepalive", default=25, type="int")

    # generate interface
    gen_server_parser = subparsers.add_parser("gen_server",
    help="generate a server profile")
    gen_server_parser.set_defaults(which="gen_server")
    gen_server_parser.add_argument("--server_interface_name", required=True)
    gen_server_parser.add_argument("--server_listen_port", required=True)
    gen_server_parser.add_argument("--")

    # todo: use jinja to load template and generate server config file

    # parse args
    args = parser.parse_args()
    return args


def run():
    args = parse_cmd_line()

    # generate private key
    if args.cmd == "gen_client":
        pass
    elif args.cmd == "gen_server":
        server_private_key = sudo[wg["genkey"]]
        print(f"server private key: {server_private_key}")

        server_public_key = sudo[wg["pubkey", server_private_key]]
        print(f"server public key: {server_public_key}")





if __name__ == "__main__":
    sys.exit(run())
