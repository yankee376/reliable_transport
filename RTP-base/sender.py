import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT_SECONDS = 0.5

START = 0
END = 1
DATA = 2
ACK = 3


def _make_packet(packet_type, seq_num, payload=b""):
    """Build an RTP packet with a CRC over a zeroed checksum field."""
    header = PacketHeader(
        type=packet_type, seq_num=seq_num, length=len(payload), checksum=0
    )
    checksum = compute_checksum(header / payload)
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=checksum,
    )
    return bytes(header / payload)


def _decode_packet(datagram):
    """Return (header, payload) for a valid packet, or None if malformed."""
    if len(datagram) < HEADER_SIZE or len(datagram) > MAX_PACKET_SIZE:
        return None

    header = PacketHeader(datagram[:HEADER_SIZE])
    payload = datagram[HEADER_SIZE:]
    if header.length != len(payload):
        return None

    checksum = header.checksum
    checksum_header = PacketHeader(
        type=header.type,
        seq_num=header.seq_num,
        length=header.length,
        checksum=0,
    )
    if compute_checksum(checksum_header / payload) != checksum:
        return None
    return header, payload


def _read_message():
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    message = stream.read()
    return message.encode() if isinstance(message, str) else message


def _wait_for_ack(sock, expected_seq_num, receiver, retry_packet=None):
    """Wait for an ACK, retrying a control packet every half second if needed."""
    while True:
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([sock], [], [], remaining)
            if not readable:
                break
            datagram, _ = sock.recvfrom(MAX_PACKET_SIZE)
            decoded = _decode_packet(datagram)
            if decoded is None:
                continue
            header, _ = decoded
            if header.type == ACK and header.length == 0:
                if header.seq_num == expected_seq_num:
                    return True
        if retry_packet is None:
            return False
        sock.sendto(retry_packet, receiver)


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    receiver = (receiver_ip, receiver_port)
    message = _read_message()
    chunks = [
        message[offset : offset + MAX_PAYLOAD_SIZE]
        for offset in range(0, len(message), MAX_PAYLOAD_SIZE)
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        start_packet = _make_packet(START, 0)
        sock.sendto(start_packet, receiver)
        _wait_for_ack(sock, 1, receiver, retry_packet=start_packet)

        data_packets = {
            seq_num: _make_packet(DATA, seq_num, chunk)
            for seq_num, chunk in enumerate(chunks, start=1)
        }
        final_data_seq = len(chunks) + 1
        base = 1
        next_seq = 1
        deadline = None

        while base < final_data_seq:
            window_end = min(final_data_seq, base + window_size)
            while next_seq < window_end:
                sock.sendto(data_packets[next_seq], receiver)
                next_seq += 1
                if deadline is None:
                    deadline = time.monotonic() + TIMEOUT_SECONDS

            if base >= next_seq:
                deadline = None
                continue

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                readable = []
            else:
                readable, _, _ = select.select([sock], [], [], remaining)

            if not readable:
                for seq_num in range(base, next_seq):
                    sock.sendto(data_packets[seq_num], receiver)
                deadline = time.monotonic() + TIMEOUT_SECONDS
                continue

            datagram, _ = sock.recvfrom(MAX_PACKET_SIZE)
            decoded = _decode_packet(datagram)
            if decoded is None:
                continue
            header, _ = decoded
            if header.type != ACK or header.length != 0:
                continue

            # A cumulative ACK N acknowledges every DATA packet below N.
            if base < header.seq_num <= next_seq:
                base = header.seq_num
                deadline = (
                    time.monotonic() + TIMEOUT_SECONDS if base < next_seq else None
                )

        end_seq = final_data_seq
        end_packet = _make_packet(END, end_seq)
        sock.sendto(end_packet, receiver)
        _wait_for_ack(sock, end_seq + 1, receiver)
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
