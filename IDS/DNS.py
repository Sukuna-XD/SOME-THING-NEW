import socket
import struct
import textwrap
from datetime import datetime
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

TAB_1 = '    '
TAB_2 = '        '
TAB_3 = '            '
TAB_4 = '                '

DATA_TAB_1 = '        '
DATA_TAB_2 = '            '
DATA_TAB_3 = '                '
DATA_TAB_4 = '                    '


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    interface = "mlan0"
    connection.bind((interface, 0))

    while True:
        #ethernet_frame
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            if proto == 17:  # UDP
                src_port, dest_port, size, checksum, payload = udp_segment(data)

                #DNS
                if src_port == 53 or dest_port == 53:
                    id, flags, q_count, ans_count, auth_count, add_count, decoded_queries, answers, authority, additional, checksum = dns_segment(payload)
                    print(f"\n[+] DNS {src} ==> {target} ({id}, {flags}, {q_count}, {ans_count}, {auth_count}, {add_count})")
                    print(TAB_1 + 'Ethernet Frame: ')
                    print(TAB_2 + 'Destination: {}, Source: {}'.format(dest_mac, src_mac))
                    print(TAB_2 + 'Protocol: {}'.format(eth_proto))
                    print(TAB_1 + 'IPv4 Packet: ')
                    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + 'Protocol: {}'.format(proto))
                    print(TAB_1 + 'DNS Segment:')
                    print(TAB_2 + f"   - ID: {id}, Flags: {flags}, Query Count: {q_count}, Answer Count: {ans_count}, Authority Count: {auth_count}, Additional Count: {add_count}")
                    print(TAB_2 + 'Queries:')
                    for query in decoded_queries:
                        print(format_multi_line(DATA_TAB_3, query))
                    print(TAB_2 + 'Answers:')
                    for answer in answers:
                        print(format_multi_line(DATA_TAB_3, answer))
                    print(TAB_2 + 'Authority:')
                    for auth in authority:
                        print(format_multi_line(DATA_TAB_3, auth))
                    print(TAB_2 + 'Additional:')
                    for add in additional:
                        print(format_multi_line(DATA_TAB_3, add))

# Helper function to format multiline data
def format_multi_line(tab, data):
    return '\n'.join(f'{tab}{line.hex().upper()}' for line in data)


            



# unpack ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# return a properly formatted mac address, i.e. (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# return a properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# unpack udp segment
def udp_segment(data):
    """
    unpacking of UDP segments.
    Unpacks UDP segments and returns all fields,
    including checksum and optional payload.
    """
    fields = '! H H 2x H'  # b - 1 byte, H - 2 bytes
    unpacked_data = struct.unpack(fields, data[:8])
    src_port, dest_port, size = unpacked_data

    # check if there is a checksum and payload
    if len(data) > 8:
        checksum = struct.unpack('! H', data[8:10])[0]
        payload = data[10:]
    else:
        checksum = 0
        payload = b''
    
    return src_port, dest_port, size, checksum, payload


# unpack DNS segment
def dns_segment(data):
    """
    Unpacks DNS segments and returns all fields,
    including questions, answers, authority, additional records,
    and the header flags.
    """
    # Unpack header fields
    id, flags, q_count, ans_count, auth_count, add_count = struct.unpack('! H H H H H H', data[:12])

    # Extract queries
    queries = []
    offset = 12  # Start after the header
    for _ in range(q_count):
        if offset >= len(data):
            break
        query_length = data[offset]
        offset += 1
        if offset + query_length > len(data):
            break
        query = data[offset:offset + query_length]
        queries.append(query)
        offset += query_length


    # Extract answers
    answers = []
    for _ in range(ans_count):
        answer_length = data[offset]
        offset += 1
        answer = data[offset:offset + answer_length]
        answers.append(answer)
        offset += answer_length

    # Extract authority records
    authority = []
    for _ in range(auth_count):
        auth_length = data[offset]
        offset += 1
        auth_record = data[offset:offset + auth_length]
        authority.append(auth_record)
        offset += auth_length

    # Extract additional records
    additional = []
    for _ in range(add_count):
        if offset >= len(data):
            break
        add_length = data[offset]
        offset += 1
        if offset + add_length > len(data):
            break
        add_record = data[offset:offset + add_length]
        additional.append(add_record)
        offset += add_length

    # Checksum placeholder (not extracted in this function)
    checksum = 0

    dns_segment = IP(data)
    decoded_payload1 = str(dns_segment[Raw].load)
    decoded_queries = decoded_payload1
    return id, flags, q_count, ans_count, auth_count, add_count, decoded_queries, answers, authority, additional, checksum


# format the multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))


if __name__ == '__main__':
    main()