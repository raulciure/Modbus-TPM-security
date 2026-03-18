import argparse
import os


def parse_args(prog_path : str):
    parser = argparse.ArgumentParser(os.path.basename(prog_path))
    parser.add_argument("host", nargs="?", type=str, metavar="HOST_IP", help="Set custom host IP address, as string")
    parser.add_argument("dest", nargs="?", type=str, metavar="SERVER_IP", help="Set custom dest IP address, as string")
    parser.add_argument("--host-ip", type=str, metavar="IP_Addr", help="Set custom host IP, as string")
    parser.add_argument("--dest-ip", type=str, metavar="IP_Addr", help="Set custom dest IP, as string")
    parser.add_argument("--measure-perf", action="store_true", help="Measure performance of the cryptographic operations")
    parser.add_argument("--set-timestamp-tolerance", type=int, metavar="SECONDS", help="Set custom timestamp tolerance for replay attack resistance, in seconds (default 1)")
    parser.add_argument("--disable-replay-resistance", action="store_true", help="Disable replay attack resistance")

    args = parser.parse_args()

    return args