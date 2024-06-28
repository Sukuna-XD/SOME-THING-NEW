import socket
import struct
import textwrap
from datetime import datetime

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
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        #print('\n[Date & Time] Protocol Srcip:srcport ==> destnip:destnport')
        #print(TAB_1 + ' - Source MAC: {}, Destination MAC: {}'.format(src_mac, dest_mac))

        # ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            
            #print(TAB_1 + ' - IPv4 Packet:')
            #print(TAB_2 + '   - Version: {}, Header Length: {}, TTL = {}'.format(version, header_length, ttl))
            if proto == 1:  # ICMP
                (icmp_type, code, checksum, identifier, sequence, payload) = icmp_packet(data)
                #icmp_type, code, checksum, identifier, sequence, payload
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ICMP {src}:{src_port} ==> {target}:{dest_port}")
                print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                print(TAB_1 + ' - ICMP Packet:')
                print(TAB_2 + f"   - Type: {icmp_type}, Code: {code}, Checksum: {checksum}".format(icmp_type, code, checksum))
                print(TAB_2 + f"   - Identifier: {identifier}, Sequence: {sequence}".format(identifier, sequence))
                print(TAB_2 + '   - Payload:')
                print(format_multi_line(DATA_TAB_3, payload))

            elif proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload) = tcp_segment(data)
                if dest_port == 443:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTPS {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + f"   - Source Port: {src_port}, Destination Port: {dest_port}".format(src_port, dest_port))
                    print(TAB_3 + f"   - Sequence: {sequence}, Acknowledgment: {acknowledgment}".format(sequence, acknowledgment))
                    #print (TAB_3 + f"Checksum: {checksum}".format(checksum))
                    print(TAB_3 + '   - Flags:')
                    print(TAB_4 + f"     - URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}".format(flag_urg, flag_ack,
                                                                                                flag_psh, flag_rst,
                                                                                                flag_syn, flag_fin))
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload))
                elif dest_port == 80:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] TCP {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + '   - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_3 + '   - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_3 + '   - Flags:')
                    print(TAB_4 + '     - URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                                flag_psh, flag_rst,
                                                                                                flag_syn, flag_fin))
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload))
            elif proto == 17:  # UDP
                src_port, dest_port, size, checksum, payload = udp_segment(data)
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] UDP {src}:{src_port} ==> {target}:{dest_port}")
                print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                print(TAB_1 + ' - UDP Segment:')
                print(TAB_2 + '   - Source Port: {}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))
                print(TAB_2 + '   - Checksum: {}'.format(checksum))
                print(TAB_2 + '   - Payload:')
                print(format_multi_line(DATA_TAB_3, payload))

            else:
                print(TAB_1 + ' - Other IPv4 Packet Type: {}'.format(proto))

        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data))


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


# unpack icmp packet
def icmp_packet(data):
    """
    Enhanced unpacking of ICMP packets.
    Unpacks ICMP packets and returns all fields.
    """
    fields = '! B B H I H'  # b - 1 byte, H - 2 bytes, I - 4 bytes
    unpacked_data = struct.unpack(fields, data[:10])
    icmp_type, code, checksum, identifier, sequence = unpacked_data
    payload = data[8:]  # rest of the packet is payload
    return icmp_type, code, checksum, identifier, sequence, payload


# unpack tcp segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# unpack HTTP and https packets

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


# format the multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))


if __name__ == '__main__':
    main()