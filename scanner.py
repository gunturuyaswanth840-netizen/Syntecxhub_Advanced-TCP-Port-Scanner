#!/usr/bin/env python3

import argparse
import csv
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


LOG_DIR = "logs"
REPORT_DIR = "reports"
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 50


def setup_logging():
    logging.basicConfig(
        filename=f"{LOG_DIR}/scanner.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(target, port, timeout):
    start_time = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            elapsed = round(time.perf_counter() - start_time, 4)

            if result == 0:
                status = "OPEN"
                service = get_service_name(port)
            elif result in (110, 110, 10060):
                status = "TIMEOUT"
                service = "-"
            else:
                status = "CLOSED"
                service = "-"

            return {
                "port": port,
                "status": status,
                "service": service,
                "response_time": elapsed
            }

    except socket.timeout:
        elapsed = round(time.perf_counter() - start_time, 4)

        return {
            "port": port,
            "status": "TIMEOUT",
            "service": "-",
            "response_time": elapsed
        }

    except Exception as error:
        logging.error(
            "Error scanning port %s: %s",
            port,
            error
        )

        return {
            "port": port,
            "status": "ERROR",
            "service": "-",
            "response_time": 0
        }


def resolve_target(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        raise ValueError(f"Unable to resolve target: {target}")


def print_banner():
    print()
    print("=" * 60)
    print("             ADVANCED TCP PORT SCANNER")
    print("=" * 60)
    print()


def print_result(result):
    port = result["port"]
    status = result["status"]
    service = result["service"]
    response = result["response_time"]

    print(
        f"{port:<10}"
        f"{status:<12}"
        f"{service:<18}"
        f"{response:.4f}s"
    )


def save_csv(results, target, start_port, end_port):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"{REPORT_DIR}/scan_{target}_"
        f"{start_port}_{end_port}_{timestamp}.csv"
    )

    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "port",
                "status",
                "service",
                "response_time"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    return filename


def scan_ports(target, start_port, end_port, threads, timeout):

    print_banner()

    print(f"Target       : {target}")
    print(f"Port Range   : {start_port}-{end_port}")
    print(f"Threads      : {threads}")
    print(f"Timeout      : {timeout}s")
    print()

    print("-" * 60)
    print(
        f"{'PORT':<10}"
        f"{'STATUS':<12}"
        f"{'SERVICE':<18}"
        f"{'TIME':<10}"
    )
    print("-" * 60)

    logging.info(
        "Starting scan: target=%s ports=%s-%s threads=%s",
        target,
        start_port,
        end_port,
        threads
    )

    start_time = time.perf_counter()

    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:

        futures = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout
            ): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):

            result = future.result()

            results.append(result)

            print_result(result)

            logging.info(
                "Port=%s Status=%s Service=%s",
                result["port"],
                result["status"],
                result["service"]
            )

    results.sort(key=lambda item: item["port"])

    elapsed = round(
        time.perf_counter() - start_time,
        2
    )

    open_ports = [
        result for result in results
        if result["status"] == "OPEN"
    ]

    closed_ports = [
        result for result in results
        if result["status"] == "CLOSED"
    ]

    timeout_ports = [
        result for result in results
        if result["status"] == "TIMEOUT"
    ]

    print("-" * 60)

    print()
    print("SCAN SUMMARY")
    print("-" * 30)
    print(f"Open Ports   : {len(open_ports)}")
    print(f"Closed Ports : {len(closed_ports)}")
    print(f"Timeouts     : {len(timeout_ports)}")
    print(f"Total Ports  : {len(results)}")
    print(f"Scan Time    : {elapsed}s")
    print()

    report = save_csv(
        results,
        target,
        start_port,
        end_port
    )

    print(f"CSV Report   : {report}")
    print(f"Log File     : {LOG_DIR}/scanner.log")
    print()

    logging.info(
        "Scan completed in %s seconds",
        elapsed
    )

    return results


def validate_ports(start_port, end_port):

    if not 1 <= start_port <= 65535:
        raise ValueError(
            "Start port must be between 1 and 65535."
        )

    if not 1 <= end_port <= 65535:
        raise ValueError(
            "End port must be between 1 and 65535."
        )

    if start_port > end_port:
        raise ValueError(
            "Start port cannot be greater than end port."
        )


def main():

    parser = argparse.ArgumentParser(
        description="Advanced TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Authorized target hostname or IP address"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-100",
        help="Port range, example: 1-1000"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help="Number of concurrent threads"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Connection timeout in seconds"
    )

    args = parser.parse_args()

    try:

        if args.threads < 1:
            raise ValueError(
                "Threads must be greater than zero."
            )

        if args.timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        if "-" not in args.ports:
            raise ValueError(
                "Port range must be written like 1-100."
            )

        start_port, end_port = map(
            int,
            args.ports.split("-", 1)
        )

        validate_ports(
            start_port,
            end_port
        )

        target_ip = resolve_target(args.target)

        print(f"Resolved target: {args.target} -> {target_ip}")

        scan_ports(
            target_ip,
            start_port,
            end_port,
            args.threads,
            args.timeout
        )

    except ValueError as error:

        print(f"[ERROR] {error}")

        logging.error(
            "Validation error: %s",
            error
        )

    except KeyboardInterrupt:

        print("\n[!] Scan interrupted by user.")

        logging.warning(
            "Scan interrupted by user."
        )

    except Exception as error:

        print(f"[ERROR] {error}")

        logging.exception(
            "Unexpected error occurred."
        )


if __name__ == "__main__":
    setup_logging()
    main()
