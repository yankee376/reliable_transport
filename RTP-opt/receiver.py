import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472

START = 0
END = 1
DATA = 2
ACK = 3


def _make_packet(packet_type, seq_num, payload=b""):
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


def receiver(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    active_sender = None
    expected_seq = 1
    buffered = {}
    output = getattr(sys.stdout, "buffer", None)

    try:
        while True:
            datagram, address = sock.recvfrom(MAX_PACKET_SIZE)
            decoded = _decode_packet(datagram)
            if decoded is None:
                continue
            header, payload = decoded

            if active_sender is None:
                if header.type != START or header.seq_num != 0 or header.length != 0:
                    continue
                active_sender = address
                expected_seq = 1
                buffered.clear()
                sock.sendto(_make_packet(ACK, 1), active_sender)
                continue

            # Ignore other senders while this connection is active.
            if address != active_sender:
                continue

            if header.type == START:
                # A connection is already active; ignore all new START packets.
                continue

            if header.type == DATA:
                seq_num = header.seq_num
                if seq_num < 1 or seq_num >= expected_seq + window_size:
                    continue

                if seq_num >= expected_seq:
                    buffered.setdefault(seq_num, payload)
                    while expected_seq in buffered:
                        chunk = buffered.pop(expected_seq)
                        if output is not None:
                            output.write(chunk)
                            output.flush()
                        else:
                            sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                            sys.stdout.flush()
                        expected_seq += 1

                # Part 3 uses an individual ACK for each accepted DATA sequence.
                sock.sendto(_make_packet(ACK, seq_num), active_sender)
                continue

            if header.type == END and header.length == 0:
                if header.seq_num == expected_seq:
                    sock.sendto(_make_packet(ACK, header.seq_num + 1), active_sender)
                    return

                # END is a control packet; sender only sends it after all DATA ACKs.
                # If it arrives early, leave the connection open for missing data.
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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
