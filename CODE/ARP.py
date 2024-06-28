import socket
import struct
from datetime import datetime, timedelta
import time
from collections import defaultdict, deque

TAB_1 = '    '
TAB_2 = '        '
TAB_3 = '            '
TAB_4 = '                '

ip_timestamps = defaultdict(deque)
log_file_udp = "/home/lashari/IDS/udp_log.csv"
log_file_flood = "/home/lashari/IDS/udp_flood_log.csv"
flood_threshold = 100  # Threshold for SYN packets in the time window
time_window = timedelta(seconds=10)  # Time window for detection
amplification_threshold = 10  # Ratio of response size to request size to flag as potential attack
request_count_threshold = 100  # Number of requests in the time window to consider an attack
ip_requests = defaultdict(lambda: {'timestamps': deque(), 'response_size': 0, 'request_size': 0})
RESERVED_DNS_TYPES = [
    'A', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'AAAA', 'SRV', 'NAPTR', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DS', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC', 'SPF', 'UNSPEC', 'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'TA', 'DLV'
]

#log_reflection_event
def log_reflection_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file_udp.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, UDP Reflection attack detected\n")

# UDP Reflection attack detection
def detect_udp_reflection(data):
    # Basic level detection
    if len(data) < 16:
        return False
    if data[0:2] != b'\x08\x00':
        return False
    if data[2:4] == data[6:8]:
        return False
    if data[4:6] == b'\x00\x00':
        return False
    if data[8:10] == b'\x00\x00':
        return False

    # Advanced level detection
    if len(data) < 64:
        return False
    if data[2:4] != data[6:8]:
        return False
    if data[4:6] != b'\x00\x00':
        return False
    if data[8:10] != b'\x00\x00':
        return False
    if data[10:12] != b'\x11\x00':
        return False
    if data[12:14] != b'\x00\x00':
        return False
    if data[14:16] != b'\x05\x00':
        return False
    if data[16:20] != b'\x00\x00\x00\x00':
        return False
    if data[20:24] != b'\x00\x00\x00\x00':
        return False
    if data[24:28] != b'\x00\x00\x00\x00':
        return False
    if data[28:32] != b'\x00\x00\x00\x00':
        return False
    if data[32:36] != b'\x00\x00\x00\x00':
        return False
    if data[32:36] != b'\x00\x00\x00\x00':
        return False
    if data[36:40] != b'\x00\x00\x00\x00':
        return False
    if data[40:44] != b'\x00\x00\x00\x00':
        return False
    if data[44:48] != b'\x00\x00\x00\x00':
        return False
    if data[48:52] != b'\x00\x00\x00\x00':
        return False
    if data[52:56] != b'\x00\x00\x00\x00':
        return False
    if data[56:60] != b'\x00\x00\x00\x00':
        return False
    if data[60:64] != b'\x00\x00\x00\x00':
        return False

    # Expert level detection
    if len(data) < 128:
        return False
    if data[64:66] != b'\x00\x00':
        return False
    if data[66:70] != b'\x00\x00\x00\x00':
        return False
    if data[70:74] != b'\x00\x00\x00\x00':
        return False
    if data[74:78] != b'\x00\x00\x00\x00':
        return False
    if data[78:82] != b'\x00\x00\x00\x00':
        return False
    if data[82:86] != b'\x00\x00\x00\x00':
        return False
    if data[86:90] != b'\x00\x00\x00\x00':
        return False
    if data[90:94] != b'\x00\x00\x00\x00':
        return False
    if data[94:98] != b'\x00\x00\x00\x00':
        return False
    if data[98:102] != b'\x00\x00\x00\x00':
        return False
    if data[102:106] != b'\x00\x00\x00\x00':
        return False
    if data[106:110] != b'\x00\x00\x00\x00':
        return False
    if data[110:114] != b'\x00\x00\x00\x00':
        return False
    if data[114:118] != b'\x00\x00\x00\x00':
        return False
    if data[118:122] != b'\x00\x00\x00\x00':
        return False
    if data[122:126] != b'\x00\x00\x00\x00':
        return False
    if data[126:130] != b'\x00\x00\x00\x00':
        return False


#log_dns_amplification_event(src)
def log_dns_amplification_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file_udp.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, DNS Amplification attack detected\n")

# DNS spoofing detection
def detect_dns_spoofing(data):
    """
    Detects if the given packet data is a spoofed DNS packet.

    Args:
        data (bytes): The packet data to be checked.

    Returns:
        bool: True if the packet is a spoofed DNS packet, False otherwise.
    """
    # Check if the packet is a DNS packet
    if data[12:14] != b'\x84\x00':
        return False

    # Check if the packet has a spoofed source IP address
    if data[26:30] != b'\x00\x00\x00\x00':
        return True

    # Check if the packet has a spoofed destination IP address
    if data[30:34] != b'\x00\x00\x00\x00':
        return True

    # Check if the packet has a spoofed source port
    if data[34:36] != b'\x00\x00':
        return True

    # Check if the packet has a spoofed destination port
    if data[36:38] != b'\x00\x00':
        return True

    # Check if the packet has a spoofed source MAC address
    if data[38:42] != b'\x00\x00\x00\x00\x00\x00':
        return True

    # Check if the packet has a spoofed destination MAC address
    if data[42:46] != b'\x00\x00\x00\x00\x00\x00':
        return True

    # Check if the packet has a spoofed source IP address in the EDNS0 option
    if len(data) > 52 and data[52:56] != b'\x00\x00\x00\x00':
        return True

    # Check if the packet has a spoofed destination IP address in the EDNS0 option
    if len(data) > 56 and data[56:60] != b'\x00\x00\x00\x00':
        return True

    # If none of the above conditions are met, return False
    return False

#log_dns_spoofing_event(src)
def log_dns_spoofing_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file_udp.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, DNS Spoofing attack detected\n")

# UDP Fragmentation Attack Detection
def detect_udp_fragmentation(data):
    """
    Detects if the given packet data is a UDP packet with a fragmented payload.

    Args:
        data (bytes): The packet data to be checked.

    Returns:
        bool: True if the packet is a fragmented UDP packet, False otherwise.
    """
    # Check if the packet is a UDP packet
    if data[12:14] != b'\x11\x00':
        return False

    # Check if the packet has a fragmented payload
    if data[20:22] != b'\x00\x00':
        return True

    # Check if the packet has a More Fragmentation flag set
    if data[22:24] == b'\x04\x00':
        return True

    # Check if the packet has a First Fragment flag set
    if data[24:26] == b'\x01\x00':
        return True

    # Check if the packet has a Next Fragment flag set
    if data[26:28] == b'\x01\x00':
        return True

    # Check if the packet has a Last Fragment flag set
    if data[28:30] == b'\x01\x00':
        return True

    # Check if the packet has a Payload Length greater than 0
    if data[30:32] != b'\x00\x00' and data[40:44] != b'\x00\x00\x00\x00':
        return True

    # Check if the packet has a Next Header set to 0x11 (UDP)
    if data[44:46] != b'\x11\x00':
        return True

    # Check if the packet has a Checksum
    if data[46:48] != b'\x00\x00':
        return True

    # Check if the packet has a Source Port
    if data[48:50] != b'\x00\x00':
        return True

    # Check if the packet has a Destination Port
    if data[50:52] != b'\x00\x00':
        return True

    # Check if the packet has a Source Address
    if data[52:56] != b'\x00\x00\x00\x00':
        return True

    # Check if the packet has a Destination Address
    if data[56:60] != b'\x00\x00\x00\x00':
        return True

    # If none of the above conditions are met, return False
    return False

#log_udp_fragmentation_event(src)
def log_udp_fragmentation_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file_udp.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, UDP Fragmentation attack detected\n")

def detect_udp_syn_flood(ip_count, ip_timestamps, ip_source):
    now = datetime.now()
    if ip_source in ip_timestamps:
        ip_timestamps[ip_source].append(now)
        # Remove timestamps older than the time window
        while ip_timestamps[ip_source] and now - ip_timestamps[ip_source][0] > time_window:
            ip_timestamps[ip_source].popleft()
        if len(ip_timestamps[ip_source]) > flood_threshold:
            return True
    else:
        ip_timestamps[ip_source] = deque([now])
    return False

def log_flood_event(ip_source):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {ip_source}, UDP SYN Flood detected\n")
        log_file.close()

# UDP amplification attack detection with sliding window
def detect_udp_amplification(ip_requests, ip_source, request_size, response_size):
    now = datetime.now()
    if ip_source in ip_requests:
        ip_requests[ip_source]['timestamps'].append(now)
        ip_requests[ip_source]['response_size'] += response_size
        ip_requests[ip_source]['request_size'] += request_size

        # Remove timestamps older than the time window
        while ip_requests[ip_source]['timestamps'] and now - ip_requests[ip_source]['timestamps'][0] > time_window:
            ip_requests[ip_source]['timestamps'].popleft()
        
        total_requests = len(ip_requests[ip_source]['timestamps'])
        if total_requests > request_count_threshold:
            average_request_size = ip_requests[ip_source]['request_size'] / total_requests
            average_response_size = ip_requests[ip_source]['response_size'] / total_requests
            amplification_ratio = average_response_size / average_request_size
            if amplification_ratio > amplification_threshold:
                return True
    else:
        ip_requests[ip_source] = {
            'timestamps': deque([now]),
            'response_size': response_size,
            'request_size': request_size
        }
    return False

def log_amplification_event(ip_source):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file_udp.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {ip_source}, UDP Amplification attack detected\n")


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    interface = "mlan0"
    connection.bind((interface, 0))
    count = 0
    while True:
        # Ethernet frame
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

            if proto == 17:  # UDP
                src_port, dest_port, size, checksum, payload = udp_segment(data)
                count += 1
                print(f"[+] UDP {src}:{src_port} ==> {target}:{dest_port}")
                print(TAB_2 + " - Ethernet frame:")
                print(TAB_3 + f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}")
                print(TAB_2 + " - IPv4 Packet:")
                print(TAB_3 + f"- Source: {src}, Destination: {target}")
                print(TAB_3 + f"- Protocol: {proto}")
                print(TAB_3 + f"- TTL: {ttl}")
                print(TAB_3 + f"- Version: {version}, Header Length: {header_length}")
                print(TAB_2 + " - UDP Segment:")
                print(TAB_3 + f"- Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
                print(TAB_3 + f"- Checksum: {checksum}")
                print(TAB_3 + f"- Payload: {payload}")
                print("\n")

                log_udp_packet(src, src_port, target, dest_port, size, checksum, payload, count)

                if detect_udp_syn_flood(count, ip_timestamps, src) == True:
                    print(f"[!] UDP SYN Flood detected from {src}")
                    log_flood_event(src)

                request_size = len(payload)
                response_size = size    

                if detect_udp_amplification(ip_requests, src, request_size, response_size) == True:
                    print(f"[!] UDP Amplification attack detected from {src}")
                    log_amplification_event(src)

                if detect_udp_reflection(data) == True:
                    print(f"[!] UDP Reflection attack detected from {src}")
                    log_reflection_event(src)

                if detect_udp_fragmentation(data) == True:
                    print(f"[!] UDP Fragmentation attack detected from {src}")
                    log_udp_fragmentation_event(src)

                if src_port == 53 or dest_port == 53:  # DNS
                    print(f"[+] DNS {src}:{src_port} ==> {target}:{dest_port}")
                    print(TAB_2 + " - Ethernet frame:")
                    print(TAB_3 + f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}")
                    print(TAB_2 + " - IPv4 Packet:")
                    print(TAB_3 + f"- Source: {src}, Destination: {target}")
                    print(TAB_3 + f"- Protocol: {proto}")
                    print(TAB_3 + f"- TTL: {ttl}")
                    print(TAB_3 + f"- Version: {version}, Header Length: {header_length}")
                    print(TAB_2 + " - UDP Segment:")
                    print(TAB_3 + f"- Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")
                    print(TAB_3 + f"- Checksum: {checksum}")
                    print(TAB_2 + ' - DNS Packet:')
                    dns_payload(payload)


                    if detect_dns_spoofing(data) == True:
                        print(f"[!] DNS Spoofing attack detected from {src}")
                        log_dns_spoofing_event(src)

                    print("\n")


# Unpack ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return a properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return a properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    checksum = struct.unpack('! H', data[8:10])[0]
    payload = data[8:]
    return src_port, dest_port, size, checksum, payload

# DNS packet unpacking
def dns_packet(data):
    id, flags, num_questions, num_answers, num_authorities, num_additional = struct.unpack('! H H H H H H', data[:12])
    return id, flags, num_questions, num_answers, num_authorities, num_additional

# Extract DNS flags
def flag_extract(flags):
    QR = flags >> 15
    opcode = (flags >> 11) & 15
    AA = (flags >> 10) & 1
    TC = (flags >> 9) & 1
    RD = (flags >> 8) & 1
    RA = (flags >> 7) & 1
    Z = (flags >> 4) & 7
    return QR, opcode, AA, TC, RD, RA, Z

# Decode DNS payload if it is DNS traffic
def dns_payload(data):
    id, flags, num_questions, num_answers, num_authorities, num_additional = dns_packet(data)
    QR, opcode, AA, TC, RD, RA, Z = flag_extract(flags)
    print(TAB_4 + f' - ID: {id}')
    print(TAB_4 + f' - Flags: {flags} (QR: {QR}, Opcode: {opcode}, AA: {AA}, TC: {TC}, RD: {RD}, RA: {RA}, Z: {Z})')
    print(TAB_4 + f' - Number of Questions: {num_questions}')
    print(TAB_4 + f' - Number of Answers: {num_answers}')
    print(TAB_4 + f' - Number of Authority Records: {num_authorities}')
    print(TAB_4 + f' - Number of Additional Records: {num_additional}')

    offset = 12  # Initial offset for the DNS header
    for i in range(num_questions):
        qname, qtype, qclass, offset = parse_dns_question(data, offset)
        print(TAB_3 + ' - Question:')
        print(TAB_4 + f' - Name: {qname}')
        print(TAB_4 + f' - Type: {qtype}')
        print(TAB_4 + f' - Class: {qclass}')

    for i in range(num_answers):
        rname, rtype, rclass, ttl, rdata, offset = parse_dns_answer(data, offset)
        print(TAB_3 + ' - Answer:')
        print(TAB_4 + f' - Name: {rname}')
        print(TAB_4 + f' - Type: {rtype}')
        print(TAB_4 + f' - Class: {rclass}')
        print(TAB_4 + f' - TTL: {ttl}')
        print(TAB_4 + f' - Data: {rdata}')

    if num_authorities > 0:
        print(TAB_3 + ' - Authority Records:')
        for i in range(num_authorities):
            aname, antype, anclass, anttl, andata, offset = parse_dns_authority(data, offset)
            print(TAB_4 + f' - Name: {aname}')
            print(TAB_4 + f' - Type: {antype}')
            print(TAB_4 + f' - Class: {anclass}')
            print(TAB_4 + f' - TTL: {anttl}')
            print(TAB_4 + f' - Data: {andata}')

    if num_additional > 0:
        print(TAB_3 + ' - Additional Records:')
        for i in range(num_additional):
            aname, antype, anclass, anttl, andata, offset = parse_dns_additional(data, offset)
            print(TAB_4 + f' - Name: {aname}')
            print(TAB_4 + f' - Type: {antype}')
            print(TAB_4 + f' - Class: {anclass}')
            print(TAB_4 + f' - TTL: {anttl}')
            print(TAB_4 + f' - Data: {andata}')

def parse_dns_question(data, offset):
    qname, offset = read_dns_name(data, offset)
    qtype, qclass = struct.unpack('! H H', data[offset:offset + 4])
    offset += 4
    return qname, qtype, qclass, offset

def parse_dns_answer(data, offset):
    rname, offset = read_dns_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack('! H H I H', data[offset:offset + 10])
    offset += 10
    rdata = data[offset:offset + rdlength]
    offset += rdlength
    return rname, rtype, rclass, ttl, rdata, offset

def parse_dns_authority(data, offset):
    aname, offset = read_dns_name(data, offset)
    antype, anclass = struct.unpack('! H H', data[offset:offset + 4])
    offset += 4
    anttl, rdlength = struct.unpack('! I H', data[offset:offset + 6])
    offset += 6
    andata = data[offset:offset + rdlength]
    offset += rdlength
    return aname, antype, anclass, anttl, andata, offset

def parse_dns_additional(data, offset):
    aname, offset = read_dns_name(data, offset)
    antype, anclass = struct.unpack('! H H', data[offset:offset + 4])
    offset += 4
    anttl, rdlength = struct.unpack('! I H', data[offset:offset + 6])
    offset += 6
    andata = data[offset:offset + rdlength]
    offset += rdlength
    return aname, antype, anclass, anttl, andata, offset

def read_dns_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if (length & 0xC0) == 0xC0:  # Pointer
            pointer = struct.unpack('! H', data[offset:offset + 2])[0]
            pointer &= 0x3FFF
            offset += 2
            labels.append(read_dns_name(data, pointer)[0])
            break
        elif length == 0:  # End of name
            offset += 1
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode('utf-8'))
            offset += length
    return '.'.join(labels), offset


def log_udp_packet(src, src_port, target, dest_port, size, checksum, payload, count):
    """
    Log TCP packet information to a log file.
    """
    now = datetime.now()
    with open(log_file_udp, 'a') as log_file:
        log_file.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, {src_port}, {target}, {dest_port}, "
                       f"{size}, {checksum}, {payload}, {count}\n")
        log_file.close()
#log_udp_fragmentation_event(src)
def log_udp_fragmentation_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, UDP Fragmentation attack detected\n")

#log_dns_spoofing_event(src)
def log_dns_spoofing_event(src):
    now = datetime.now()
    with open(log_file_flood, 'a') as log_file:
        log_file.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, DNS Spoofing attack detected\n")

if __name__ == '__main__':
    main()
