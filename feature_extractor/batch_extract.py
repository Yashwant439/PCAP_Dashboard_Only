import os
import sys
import subprocess


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

CAPTURE_DIR = os.path.join(
    PROJECT_DIR,
    "pcap_factory",
    "captures"
)

EXTRACTOR = os.path.join(
    SCRIPT_DIR,
    "extractor.py"
)


def main():
    print("=" * 70)
    print("IPsec PCAP BATCH FEATURE EXTRACTION")
    print("=" * 70)

    if not os.path.isdir(CAPTURE_DIR):
        print(f"ERROR: Capture directory not found:")
        print(CAPTURE_DIR)
        sys.exit(1)

    pcaps = sorted(
        filename
        for filename in os.listdir(CAPTURE_DIR)
        if filename.lower().endswith(".pcap")
    )

    if not pcaps:
        print("ERROR: No PCAP files found.")
        sys.exit(1)

    print()
    print(f"Capture directory: {CAPTURE_DIR}")
    print(f"PCAP files found : {len(pcaps)}")
    print()

    successful = 0
    failed = 0

    for index, filename in enumerate(pcaps, start=1):
        pcap_path = os.path.join(
            CAPTURE_DIR,
            filename
        )

        print("-" * 70)
        print(f"[{index}/{len(pcaps)}] {filename}")
        print("-" * 70)

        result = subprocess.run(
            [
                sys.executable,
                EXTRACTOR,
                pcap_path
            ]
        )

        if result.returncode == 0:
            successful += 1
        else:
            failed += 1
            print()
            print(f"FAILED: {filename}")

    print()
    print("=" * 70)
    print("BATCH EXTRACTION COMPLETE")
    print("=" * 70)
    print(f"Total PCAPs : {len(pcaps)}")
    print(f"Successful  : {successful}")
    print(f"Failed      : {failed}")
    print("=" * 70)


if __name__ == "__main__":
    main()