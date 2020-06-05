#!/usr/bin/pyton3

import sys
import argparse
from plumbum.cmd import sudo, wg
from jinja2 import Environment, FileSystemLoader

class Config:
    def __init__(self):
        super().__init__()


def parse_cmd_line() -> Config:
    parser = argparse.ArgumentParser()

    parser.add_argument("--pre_up", default="")
    parser.add_argument("--post_up", default="")
    parser.add_argument("--pre_down", default="")
    parser.add_argument("--post_down", default="")
    parser.add_argument("--table", default="auto")
    parser.add_argument("--table_off", action="store_true")
    parser.add_argument("--address", required=True)
    parser.add_argument("--name", default="")
    parser.add_argument("--mtu", default="")
    parser.add_argument("--server_interface", required=True)

    subparsers = parser.add_subparsers()
    # generate client
    gen_client_parser = subparsers.add_parser("gen_client", help="generate a client profile")
    gen_client_parser.set_defaults(which="gen_client")
    gen_client_parser.add_argument("--server_config", required=True)
    gen_client_parser.add_argument("--allowed_ips", default="0.0.0.0/0")
    gen_client_parser.add_argument("--persistent_keepalive", default=25, type="int")

    # generate interface
    gen_server_parser = subparsers.add_parser("gen_server",
    help="generate a server profile")
    gen_server_parser.set_defaults(which="gen_server")
    gen_server_parser.add_argument("--server_listen_port", default="51820")

    # parse args
    args = parser.parse_args()
    return args


def run():
    args = parse_cmd_line()

    env = Environment(
        loader=FileSystemLoader("./")
    )

    dns_list = []
    if len(dns_list) > 0:
        _dns_list = ",".join(x for x in dns_list)
        dns = f"DNS = {_dns_list}"
    else:
        dns = ""
    mtu = ""
    if args.mtu != "":
        mtu = f"MTU = {args.mtu}"

    private_key = sudo[wg["genkey"]]
    print(f"private key: {private_key}")

    public_key = sudo[wg["pubkey", private_key]]
    print(f"public key: {public_key}")

    # generate private key
    if args.cmd == "gen_client":
        template = env.get_template("client.j2")
        client_blob = template.render(
            address = args.address,
            private_key = private_key,
            dns = dns,
            mtu = mtu,
            table = table,
        )
    elif args.cmd == "gen_server":
        template = env.get_template("server.j2")

        server_blob = template.render(
            server_address = server_address,
            server_private_key = server_private_key,
            server_listen_port = server_listen_port
        )

if __name__ == "__main__":
    sys.exit(run())
