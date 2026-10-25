#!/usr/bin/env python3
import argparse
import hashlib
import importlib
import json
import os
import re
import socket
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# The distributed source may be named attachments.py; accept the singular
# attachment.py name as a fallback so the same solver works either way.
CHALLENGE_FILE = next(
    (
        name
        for name in ("attachments.py", "attachment.py")
        if os.path.exists(os.path.join(BASE_DIR, name))
    ),
    "attachments.py",
)
challenge = importlib.import_module(os.path.splitext(CHALLENGE_FILE)[0])
G = challenge.G
N = challenge.N
scalar_mult = challenge.scalar_mult
from fpylll import IntegerMatrix, LLL


class Pipe:
    """Small buffered byte pipe used for both a local process and TCP."""

    def __init__(self, read_chunk, write_chunk, close=lambda: None):
        self._read_chunk = read_chunk
        self._write_chunk = write_chunk
        self._close = close
        self.buf = b""

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self._read_chunk(4096)
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(marker)
        if idx < 0:
            out, self.buf = self.buf, b""
            return out
        end = idx + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def recv_all(self) -> bytes:
        out = self.buf
        self.buf = b""
        while True:
            chunk = self._read_chunk(4096)
            if not chunk:
                return out
            out += chunk

    def sendline(self, data: bytes):
        self._write_chunk(data + b"\n")

    def close(self):
        self._close()


def local_pipe() -> Pipe:
    here = os.path.dirname(os.path.abspath(__file__))
    server = os.path.join(here, CHALLENGE_FILE)
    proc = subprocess.Popen(
        [sys.executable, server, "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    def write_chunk(data: bytes):
        proc.stdin.write(data)
        proc.stdin.flush()

    def close():
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass

    return Pipe(
        lambda n: os.read(proc.stdout.fileno(), n),
        write_chunk,
        close,
    )


def remote_pipe(host: str, port: int, timeout: float) -> Pipe:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return Pipe(sock.recv, sock.sendall, sock.close)


def recover_d(sigs, Q):
    # sigs: list of dict(z,r,s).  For every signature:
    # k = s^-1 (z + r*d) = a*d + b (mod N)
    ab = []
    for sig in sigs:
        inv_s = pow(sig["s"], -1, N)
        ab.append(((sig["r"] * inv_s) % N, (sig["z"] * inv_s) % N))

    # All nonces share their first 20 bytes.  Subtracting signature 0:
    # A_i*d + B_i == k_i-k_0 (mod N), where |k_i-k_0| < 2^96.
    B = 1 << 96
    X = 2 * B
    A = []
    Bc = []
    a0, b0 = ab[0]
    for a, b in ab[1:]:
        A.append((a - a0) % N)
        # Offset the signed error from (-B,B) to (0,2B).
        Bc.append((b - b0 + B) % N)

    m = len(A)
    dim = m + 2
    M = IntegerMatrix(dim, dim)

    # Mod-N basis rows (scaled).
    for i in range(m):
        M[i, i] = N * N

    # d row.
    for i in range(m):
        M[m, i] = A[i] * N
    M[m, m] = X

    # Constant / embedding row.
    for i in range(m):
        M[m + 1, i] = Bc[i] * N
    M[m + 1, m + 1] = N * X

    M = LLL.reduction(M)

    for row in M:
        vals = [int(x) for x in row]
        if vals[m] % X != 0:
            continue

        # Coefficient of the d row. A reduced vector may encode this as
        # d, -d, or d modulo N (for example d-N), depending on which
        # equivalent short vector LLL returns.
        t = vals[m] // X
        candidates = {t % N}

        # The last coordinate is c*N*X, where c is the coefficient of
        # the constant row. For c times (possibly negated) target
        # vector, t/c is d modulo N.
        if vals[m + 1] % (N * X) == 0:
            c = vals[m + 1] // (N * X)
            if c and c % N:
                candidates.add((t * pow(c % N, -1, N)) % N)

        for cand in candidates:
            if 1 <= cand < N and scalar_mult(cand, G) == Q:
                return cand
    raise RuntimeError("lattice attack did not recover d")


def exploit(io: Pipe):
    banner = io.recv_until(b"> ").decode()
    print(banner)

    Qx = int(re.search(r"Public Key Qx : (0x[0-9a-fA-F]+)", banner).group(1), 16)
    Qy = int(re.search(r"Public Key Qy : (0x[0-9a-fA-F]+)", banner).group(1), 16)
    target = re.search(r"Vault Target  : (.+)", banner).group(1).strip().encode()
    Q = (Qx, Qy)

    sigs = []
    for i in range(5):
        msg = f"audit-message-{i}".encode()
        io.sendline(b"1")
        io.recv_until(b"Enter message in hex: ")
        io.sendline(msg.hex().encode())
        out = io.recv_until(b"> ").decode()
        data = json.loads(re.search(r"Signature generated: (\{.*\})", out).group(1))
        sig = {k: int(data[k], 16) for k in ("z", "r", "s")}
        sigs.append(sig)
        print(f"sig[{i}] r={hex(sig['r'])} s={hex(sig['s'])}")

    d = recover_d(sigs, Q)
    print(f"[+] recovered private key d = {hex(d)}")
    assert scalar_mult(d, G) == Q

    # Forge a fresh, valid ECDSA signature for the one-time target command.
    z = int.from_bytes(hashlib.sha256(target).digest(), "big") % N
    k = 0xC0FFEE
    R = scalar_mult(k, G)
    r = R[0] % N
    s = (pow(k, -1, N) * (z + r * d)) % N
    print(f"[+] forged r = {hex(r)}")
    print(f"[+] forged s = {hex(s)}")

    io.sendline(b"2")
    io.recv_until(b"Enter signature r (hex or int): ")
    io.sendline(hex(r).encode())
    io.recv_until(b"Enter signature s (hex or int): ")
    io.sendline(hex(s).encode())

    final = io.recv_all().decode(errors="ignore")
    print(final)
    m = re.search(r"IONIC\{[^}]+\}", final)
    if not m:
        raise RuntimeError("flag not found in server response")
    print(f"[FLAG] {m.group(0)}")
    return m.group(0)


def main():
    parser = argparse.ArgumentParser(
        description="Exploit the Chronos HSM Vault ECDSA nonce flaw"
    )
    parser.add_argument("--host", help="remote challenge host; omit for local stdio mode")
    parser.add_argument("--port", type=int, help="remote challenge port")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="TCP connect/read timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    if bool(args.host) != bool(args.port):
        parser.error("--host and --port must be supplied together")

    if args.host:
        print(f"[*] Connecting to {args.host}:{args.port} ...")
        io = remote_pipe(args.host, args.port, args.timeout)
    else:
        print(f"[*] Starting local {CHALLENGE_FILE} in --stdio mode ...")
        io = local_pipe()

    try:
        exploit(io)
    finally:
        io.close()


if __name__ == "__main__":
    main()
