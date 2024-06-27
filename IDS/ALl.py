import struct
import socket
import socket
import struct
import textwrap
import datetime as datetime
from datetime import datetime, timedelta
from collections import defaultdict, deque
from scapy.layers.inet import IP
from scapy.all import *
import re
from urllib.parse import unquote

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

XSS_PAYLOADS_FILE = "/home/lashari/IDS/XSS_Payloads.txt"
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
threshold = 1000
SYN_FLOOD_PACKET_RATE_THRESHOLD = 1000  # Set an appropriate threshold
injection_keywords = ['SELECT', 'UPDATE', 'DELETE', 'INSERT', 'DROP', 'TRUNCATE', 'UNION', 'EXEC', 'SCRIPT', 'JAVASCRIPT', 'PHP', 'PYTHON', 'RUBY', 'PERL', 'JAVA', 'C++', 'C#']
MALICIOUS_PATTERNS = [
    b'bash',
    b'nc',
    b'telnet',
    b'ssh',
    b'ftp',
    b'perl',
    b'python',
    b'java',
    b'ruby',
    b'php',
    b'php3',
    b'php4',
    b'php5',
    b'php6',
    b'php7',
    b'php8',
    b'asp',
    b'aspx',
    b'js',
    b'jsp',
    b'jspx',
    b'py',
    b'pyp',
    b'pyc',
    b'pyo',
    b'pyz',
    b'html',
    b'htm',
    b'js',
    b'js2',
    b'js3',
    b'js4',
    b'js5',
    b'js6',
    b'js7',
    b'js8',
    b'css',
    b'js',
    b'jsex',
    b'jspa',
    b'json',
    b'bat',
    b'cmd',
    b'com',
    b'exe',
    b'pyc',
    b'pyo',
    b'pyz',
    b'gz',
    b'z',
    b'z2',
    b'zip',
    b'rar',
    b'iso',
    b'iso966',
    b'dmg',
    b'vmdk',
    b'vdi',
    b'vhd',
    b'shd',
    b'iso966',
    b'udf',
    b'ext',
    b'ext2',
    b'ext3',
    b'ext4',
    b'hfs',
    b'hfs+',
    b'reiserfs',
    b'jfs',
    b'xfs',
    b'ntfs',
    b'fat',
    b'fat32',
    b'ntfs',
    b'ntfs5',
    b'ntfs6',
    b'ntfs7',
    b'ntfs8',
    b'zip',
    b'rar',
    b'7z',
    b'arj',
    b'cab',
    b'lzh',
    b'lzma',
    b'xz',
    b'tar',
    b'gz',
    b'bz2',
    b'xz2',
    b'7z2',
    b'zipx',
    b'zst',
    b'asci',
    b'pdf',
    b'docx',
    b'docm',
    b'xlsx',
    b'xlsm',
    b'pptx',
    b'pptm',
    b'ppt',
    b'ods',
    b'odt',
    b'odp',
    b'odb',
    b'odg',
    b'ogg',
    b'oga',
    b'otf',
    b'webm',
    b'webp',
    b'woff',
    b'woff2',
    b'eot',
    b'ttf',
    b'png',
    b'gif',
    b'jpg',
    b'jpeg',
    b'ico',
    b'cur',
    b'bin',
    b'iso',
    b'img',
    b'jpg',
    b'jpeg',
    b'png',
    b'gif',
    b'pdf',
    b'pdfa',
    b'pdfx',
    b'ps',
    b'dvi',
    b'svg',
    b'tif',
    b'tiff',
    b'bmp',
    b'dib',
    b'rle',
    b'rgba',
    b'xpm',
    b'xbm',
    b'xwd',
    b'x11',
    b'pnm',
    b'pbm',
    b'pgm',
    b'ppm',
    b'tga',
    b'tga',
    b'sgi',
    b'sun',
    b'pcx',
    b'pict',
    b'pic',
    b'pbm',
    b'pgm',
    b'ppm',
    b'pgb',
    b'pgm',
    b'ppm',
    b'ppm',
    b'xpm',
    b'xbm',
    b'xwd',
    b'x11',
    b'gif',
    b'jpeg',
    b'jpeg',
    b'png',
    b'png',
    b'tif',
    b'tiff',
    b'bmp',
    b'dib',
    b'rle',
    b'rgba',
    b'xpm',
    b'xbm',
    b'xwd',
    b'x11',
    b'pnm',
    b'pbm',
    b'pgm',
    b'ppm',
    b'tga',
    b'tga',
    b'sgi',
    b'sun',
    b'pcx',
    b'pict',
    b'pic',
    b'tga',
    b'tga',
    b'sgi',
    b'sun',
    b'pcx',
    b'pict',
    b'pic',
    b'gif',
    b'jpeg',
    b'jpeg',
    b'png',
    b'png',
    b'tif',
    b'tiff',
    b'bmp',
    b'dib',
    b'rle',
    b'rgba',
    b'xpm',
    b'xbm',
    b'xwd',
    b'x11',
    b'pnm',
    b'pbm',
    b'pgm',
    b'ppm',
    b'tga',
    b'tga',
    b'sgi'
    ]

log_file_tcp = "/home/lashari/IDS/tcp_logs.csv"

SYN_FLOOD_THRESHOLD = 50  # Set an appropriate threshold
TIME_WINDOW = timedelta(seconds=1)  # Time window to monitor SYN packets

# Dictionary to store SYN packets count per source IP
syn_counts = defaultdict(list)

#Log file for UDP
log_file_udp = '/home/lashari/IDS/udp_logs.csv'

THRESHOULD = 10
MAX_ALLOWED_SIZE = 1473

#ICMP code meaning
type_names = {
        0: 'Echo Reply',
        3: 'Time Exceeded',
        4: 'Parameter Problem',
        5: 'Redirect Message',
        8: 'Echo Request',
        11: 'Time-TO-LIVE Exceeded',
        12: 'Address Mask Request',
        13: 'Address Mask Reply',
        14: 'Timestamp',
        15: 'Timestamp Reply',
        16: 'Information Request',
        17: 'Information Reply',
        18: 'Address Mapping',
        19: 'Address Mapping Reply'
    }

log_file_icmp = '/home/lashari/IDS/icmp_logs.csv'
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

attacker_ips = []
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    ip_address_set = set()  # Set to store IP addresses of detected ICMP ping flood attacks
    ip_count_dict = {}
    count = 0
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            #ICMP
            if proto == 1:
                icmp_type, code, checksum, identifier, sequence, decoded_payload, type_name = icmp_packet(data)

                print (f"\n[+] ICMP {src} ==> {target}")
                print(TAB_1 + 'Ethernet Frame: ')
                print(TAB_2 + 'Destination: {}, Source: {}'.format(dest_mac, src_mac))
                print(TAB_2 + 'Protocol: {}'.format(eth_proto))
                print(TAB_1 + 'IPv4 Packet: ')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}'.format(proto))
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Identifier: {}, Sequence: {}'.format(identifier, sequence))
                print(TAB_2 + 'Type: {}'.format(type_name))
                print(TAB_2 + 'Payload:')
                print(format_multi_line(DATA_TAB_3, decoded_payload))

                count += 1
                log_icmp(timestamp, src, count, log_file_icmp, icmp_type, code, identifier, sequence)
                if ping_flood(data, ip_address_set, ip_count_dict) == True:
                    print(TAB_2 + "[##] PING FLOOD DETECTED")
                    attacker_ips.append(src)

                    block_ip(src)
                    print ("\n")

                if ping_death(data, ip_address_set) == True:
                    print (TAB_2 + "[##] PING DEATH DETECTED")
                    attacker_ips.append(src)
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', src, '-p', 'icmp', '-j', 'DROP'])
                    block_ip(src)  
                    print ("\n")

                if detect_icmp_smurf_attack(log_file_icmp):
                    print (TAB_2 + "[##] ICMP SMURF ATTACK DETECTED")   
                    attacker_ips.append(src)
                    block_ip()
                    print ("\n")

                if detect_icmp_time_exceeded_attack(log_file_icmp):
                    print (TAB_2 + "[##] ICMP TIME EXCEEDED ATTACK DETECTED")
                    attacker_ips.append(src)
                    block_ip()
                    print ("\n")

                if detect_icmp_destination_unreachable_attack(log_file_icmp):
                    print (TAB_2 + "[##] ICMP DESTINATION UNREACHABLE ATTACK DETECTED")
                    attacker_ips.append(src)
                    block_ip()
                    print ("\n")

                if detect_icmp_redirection_attack(icmp_type, log_file_icmp):
                    print (TAB_2 + "[##] ICMP REDIRECTION ATTACK DETECTED")
                    attacker_ips.append(src)
                    #block_attacker_ips()
                    print ("\n")

            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size,urgent_pointer, decoded_payload, offset = tcp_segment(data)
                payload_length=len(decoded_payload)
                print(f"\n [+] TCP {src}:{src_port} ==> {target}:{dest_port}")
                print(TAB_1 + " - Ethernet frame:")
                print(TAB_2 + f"    - Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                print(TAB_2 +  f"    - Protocol: {eth_proto}".format(eth_proto))
                print(TAB_1 + ' - IPv4 Packet:')
                print(TAB_2 + '    - Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + f'    - Protocol: {proto}'.format(proto))
                print(TAB_1 + ' - TCP Segment:')
                print(TAB_2 + f"    - Source Port: {src_port}, Destination Port: {dest_port}".format(src_port, dest_port))
                print(TAB_2 + f"    - Sequence: {sequence}, Acknowledgment: {acknowledgment}".format(sequence, acknowledgment))
                print(TAB_2 + f"    - Window Size: {window_size}".format(window_size))
                print(TAB_2 + f"    - Urgent Pointer: {urgent_pointer}".format(urgent_pointer))
                print(TAB_2 + '    - Flags:')
                print(TAB_3 + f"     - URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}".format(flag_urg, flag_ack,
                                                                                                flag_psh, flag_rst,
                                                                                                flag_syn, flag_fin))
                print(TAB_1 + ' - Payload Length: {payload_length}'.format(payload_length=payload_length))
                print(TAB_1 + ' - Payload:')
                print(format_multi_line(DATA_TAB_3, decoded_payload) )
                
                count += 1

                log_tcp_packet(src, src_port, target, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, urgent_pointer, count)
                
                if detect_syn_flood(src) == True:
                    print (TAB_1 + "[##] SYN Flood Detected")

                if detect_tcp_window_manipulation(window_size) == True:
                    print (TAB_1 + "[##] TCP window Manipulation Detected")    
                
                #if detect_tcp_session_hijacking(src, src_port, target, dest_port, sequence, flag_ack, flag_psh, flag_rst, flag_syn, decoded_payload, acknowledgment, log_file_tcp, flag_urg, flag_fin, window_size, urgent_pointer) == True: 
                 
                #   print (TAB_1 + "[##] TCP Session Hijacking attack detected")
                if detect_tcp_reset_attack(flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, count, threshold, log_file_tcp) == True:
                    print (TAB_1 + "[##] TCP Reset Attack Detected")

                #if detect_tcp_fragmentation_attack(offset, window_size, payload_length, decoded_payload) == True:
                 #   print (TAB_1 + "[##] TCP Fragmentation Attack Detected")        

                if detect_tcp_injection_attack(src, src_port, target, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, urgent_pointer, decoded_payload) == True:
                    print (TAB_1 + "[##] Advanced TCP Injection Attack Detected")    

                if detect_tcp_syn_and_ack_attack(flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, count, threshold, log_file_tcp) == True:
                    print (TAB_1 + "[##] TCP SYN and ACK Attack Detected")    

                if detect_land_attack(src, target, log_file_tcp) == True:
                    print (TAB_1 + "[##] Land Attack Detected")   

                if dest_port == 80:
                    (request_method, url, http_version, headers, decoded_payload) = http_segment(data)
                    print(TAB_1 + " - Ethernet frame:")
                    print(TAB_2 + f"    - Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 +  f"    - Protocol: {eth_proto}".format(eth_proto))
                    print(TAB_1 + ' - IPv4 Packet:')
                    print(TAB_2 + '    - Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                    print(TAB_2 + f'    - Protocol: {proto}'.format(proto))
                    print(TAB_1 + ' - TCP Segment:')
                    print(TAB_2 + f"    - Source Port: {src_port}, Destination Port: {dest_port}".format(src_port, dest_port))
                    print(TAB_2 + f"    - Sequence: {sequence}, Acknowledgment: {acknowledgment}".format(sequence, acknowledgment))
                    print(TAB_2 + f"    - Window Size: {window_size}".format(window_size))
                    print(TAB_2 + f"    - Urgent Pointer: {urgent_pointer}".format(urgent_pointer))
                    print(TAB_3 + '   - Flags:')
                    print(TAB_4 + '     - URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_1 + f'HTTP Segment: ')
                    print(TAB_2 + '   - Request Method: {}, URL: {}, HTTP Version: {}'.format(request_method, url, http_version))
                    print(TAB_2 + '   - Headers:')
                    print(format_multi_line(DATA_TAB_3, headers))
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, decoded_payload))
                    if detect_xss(decoded_payload):
                        print("\033[91m XSS Detected \033[00m")
                        log_xss_payload(decoded_payload)
            elif proto == 17:  # UDP
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

def block_ip(ip_address):
    try:
        command = ['iptables', '-A', 'INPUT', '-s', ip_address, '-p', 'icmp', '-j', 'DROP']
        print("Executing command:", ' '.join(command))
        subprocess.run(command, check=True)
        print(f"Blocked ICMP traffic from {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block ICMP traffic from {ip_address}: {e}")



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
    # Check if the packet data length is sufficient for ICMP header
    if len(data) < 12:
        print("Error: Insufficient data length for ICMP header")
        return None, None, None, None, None, None, None

    fields = '! B B H L L'  # b - 1 byte, B - 2 bytes, H - 4 bytes, L - 4 bytes

    try:
        unpacked_data = struct.unpack(fields, data[:12])
    except struct.error:
        print("Error: Failed to unpack ICMP header")
        return None, None, None, None, None, None, None

    icmp_type, code, checksum, identifier, sequence = unpacked_data
    payload = data[8:]  # rest of the packet is payload
    if icmp_type in type_names:
        type_name = type_names[icmp_type]
    else:
        type_name = 'Unknown'

    payload = data[8:12]

    return icmp_type, code, checksum, identifier, sequence, payload, type_name


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


# format the multi-line data
def format_multi_line(prefix, string, size=80):
    """
    Format the multi-line data.
    :param prefix: The prefix for each line.
    :param string: The string to format.
    :param size: The size of each line.
    :return: The formatted string.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    if string is not None:
        return '\n'.join(prefix + line for line in textwrap.wrap(string, size)
                        if string is not None)
    else:
        return "No payload data"

# Log ICMP details in the specified format.
def log_icmp(timestamp: str, ip_address: str, count: int, log_file: str, icmp_type: str, icmp_code: str, identifier: int, sequence: int) -> None:
    """
    Log ICMP details in the specified format.

    :param timestamp: The timestamp of the log entry.
    :param ip_address: The IP address associated with the log entry.
    :param count: The count of ICMP packets.
    :param packet_type: The type of ICMP packet.
    :param packet_code: The code of ICMP packet.
    :param log_file: The path to the log file.
    :param icmp_type: The type of ICMP packet.
    :param icmp_code: The code of ICMP packet.
    :param identifier: The identifier of ICMP packet.
    :param sequence: The sequence of ICMP packet.
    """
    log_entry = f"{timestamp}, {ip_address}, {count}, {icmp_type}, {icmp_code}, {identifier}, {sequence}\n"

    try:
        with open(log_file, 'a') as f:
            f.write(log_entry)
    except IOError as e:
        print(f"Error writing to log file: {e}")

def ping_death(data, ip_address_set):
    """
    Ping of Death:
    Identification: Detection of ICMP Echo Request packets with sizes exceeding the maximum packet size allowed by the network stack.
    Packet Information: Analyze ICMP Echo Request packets for unusually large sizes that may indicate malformed or oversized packets.

    :param data: The ICMP packet data.
    :param ip_address_set: The set of IP addresses associated with the ICMP packets.
    :return: True if the ICMP packet is a Ping of Death, False otherwise.
    """
    # Check if the packet data length is sufficient for ICMP header
    if len(data) < 20:
        print("Error: Insufficient data length for ICMP header")
        return False

    # Extract the ICMP header
    try:
        icmp_header = data[20:22]
        icmp_type, icmp_code = struct.unpack('BB', icmp_header)
    except struct.error:
        print("Error: Failed to unpack ICMP header")
        return False

    # Check if the ICMP packet size exceeds the maximum allowed size
    if len(data) > MAX_ALLOWED_SIZE:
        return True

    return False

def is_fragmented(data):
    """
    Check if the ICMP packet is fragmented.

    :param data: The ICMP packet data.
    :return: True if the packet is fragmented, False otherwise.
    """
    # Extract the fragmentation offset and more fragments flag from the IP header
    offset, mf_flag = struct.unpack("!HH", data[6:10])
    
    # Check if the more fragments flag is set or the offset is nonzero
    return (offset > 0) or (mf_flag & 0x2000)


def get_network_stack_limit():
    """
    Get the maximum allowed size for an ICMP packet from the network stack.

    :return: Maximum allowed size for an ICMP packet.
    """
    # Implement logic to retrieve the maximum allowed size from the network stack
    return 1472  # Placeholder implementation

#ICMP SMURF Attack
def detect_icmp_smurf_attack(log_file):
    """
    ICMP Smurf Attack detection implementation.

    :param log_file: The log file containing network activity logs.
    :return: True if a Smurf attack is detected, False otherwise.
    """
    ICMP_SMURF_ATTACK_THRESHOLD = 10
    ICMP_SMURF_ATTACK_WINDOW = 60

    icmp_packets = 0
    icmp_smurf_attack_detected = False
    icmp_attack_window_start = None
    icmp_timestamps = set()  # Use a set to automatically remove duplicates

    try:
        with open(log_file, 'r') as f:
            for line in f:
                log = line.strip().split(',')
                if len(log) >= 2 and log[1] == 'ICMP':
                    icmp_packets += 1
                    current_time = datetime.datetime.strptime(log[0], '%Y-%m-%d %H:%M:%S')
                    if icmp_attack_window_start is None:
                        icmp_attack_window_start = current_time
                    elif (current_time - icmp_attack_window_start).total_seconds() < ICMP_SMURF_ATTACK_WINDOW:
                        icmp_timestamps.add(current_time)
                        if len(icmp_timestamps) > ICMP_SMURF_ATTACK_THRESHOLD:
                            if (datetime.datetime.now() - icmp_timestamps[-ICMP_SMURF_ATTACK_THRESHOLD - 1]).total_seconds() < ICMP_SMURF_ATTACK_WINDOW:
                                icmp_smurf_attack_detected = True
                                break
                    else:
                        icmp_packets = 1
                        icmp_attack_window_start = current_time
                        icmp_timestamps = set([current_time])
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error parsing log file '{log_file}': {e}")

    return icmp_smurf_attack_detected

#PING FLOOD
def ping_flood(data, ip_address_set, ip_count_dict):
    """
    Ping Flood detection

    :param data: The ICMP packet data.
    :param ip_address_set: The set of detected ICMP ping flood IP addresses.
    :param ip_count_dict: A dictionary to store the count for each victim IP address.
    :return: True if a ping flood attack is detected, False otherwise.
    """
    fields = '! B B H L L'  # b - 1 byte, B - 2 bytes, H - 4 bytes, L - 4 bytes
    if len(data) < 12:
        return False

    try:
        unpacked_data = struct.unpack(fields, data[:12])
    except struct.error:
        print("Error: Insufficient data length for ICMP header")
        return False

    icmp_type, code, checksum, identifier, sequence = unpacked_data
    payload = data[8:]  # rest of the packet is payload

    detected = False

    if icmp_type == 8 and code == 0 and identifier > 0 and sequence > 0:
        victim_ip = ipv4(icmp_packet(data)[5])  # Extracting victim IP from the tuple
        if victim_ip not in ip_address_set:
            ip_address_set.add(victim_ip)
            ip_count_dict[victim_ip] = 1  # Initialize count for the new victim IP
        else:
            ip_count_dict[victim_ip] += 1  # Increment count for existing victim IP

        if ip_count_dict[victim_ip] >= THRESHOULD:  # Check if the count exceeds the threshold
            detected = True

    return detected

def detect_icmp_time_exceeded_attack(log_file):
    """
    ICMP Time Exceeded Attack detection implementation.

    :param log_file: The log file containing network activity logs.
    :return: True if a Time Exceeded attack is detected, False otherwise.
    """
    ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD = 10
    ICMP_TIME_EXCEEDED_ATTACK_WINDOW = 60

    icmp_packets = 0
    icmp_time_exceeded_attack_detected = False
    icmp_attack_window_start = None
    icmp_timestamps = set()  # Use a set to automatically remove duplicates

    ip_address_set = set()
    ip_count_dict = {}

    try:
        with open(log_file, 'r') as f:
            for line in f:
                log = line.strip().split(',')
                if len(log) >= 2 and log[1] == 'Time Exceeded':
                    icmp_packets += 1
                    current_time = datetime.datetime.strptime(log[0], '%Y-%m-%d %H:%M:%S')
                    if icmp_attack_window_start is None:
                        icmp_attack_window_start = current_time
                    elif (current_time - icmp_attack_window_start).total_seconds() < ICMP_TIME_EXCEEDED_ATTACK_WINDOW:
                        icmp_timestamps.add(current_time)
                        if len(icmp_timestamps) > ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD:
                            # Ensure robust comparison of timestamps
                            if (datetime.datetime.now() - sorted(icmp_timestamps)[-ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD]).total_seconds() < ICMP_TIME_EXCEEDED_ATTACK_WINDOW:
                                icmp_time_exceeded_attack_detected = True
                                break
                    else:
                        icmp_packets = 1
                        icmp_attack_window_start = current_time
                        icmp_timestamps = set([current_time])
                elif len(log) >= 2 and log[1] == 'Echo':
                    if ping_flood(log[2], ip_address_set, ip_count_dict):
                        print("Ping Flood attack detected!")
                        return True  # Exit early if a ping flood attack is detected
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error parsing log file '{log_file}': {e}")

    return icmp_time_exceeded_attack_detected

#DESTINATION UNREACHABLE Attack
def detect_icmp_destination_unreachable_attack(log_file):
    """
    ICMP Destination Unreachable Attack detection implementation.

    :param log_file: The log file containing network activity logs.
    :return: True if a Destination Unreachable attack is detected, False otherwise.
    """
    ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD = 10
    ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW = 60

    icmp_packets = 0
    icmp_destination_unreachable_attack_detected = False
    icmp_attack_window_start = None
    icmp_timestamps = set()  # Use a set to automatically remove duplicates

    try:
        with open(log_file, 'r') as f:
            for line in f:
                log = line.strip().split(',')
                if len(log) >= 2 and log[1] == 'Destination Unreachable':
                    icmp_packets += 1
                    current_time = datetime.datetime.strptime(log[0], '%Y-%m-%d %H:%M:%S')
                    if icmp_attack_window_start is None:
                        icmp_attack_window_start = current_time
                    elif (current_time - icmp_attack_window_start).total_seconds() < ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW:
                        icmp_timestamps.add(current_time)
                        if len(icmp_timestamps) > ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD:
                            if (datetime.datetime.now() - sorted(icmp_timestamps)[-ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD]).total_seconds() < ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW:
                                icmp_destination_unreachable_attack_detected = True
                                break
                    else:
                        icmp_packets = 1
                        icmp_attack_window_start = current_time
                        icmp_timestamps = set([current_time])
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error parsing log file '{log_file}': {e}")

    return icmp_destination_unreachable_attack_detected

def detect_icmp_redirection_attack(icmp_type, log_file):

    """
    ICMP Redirection Attack detection implementation.
    """
    detected = False
    if icmp_type == 5:
        detected = True    

    return detected
    
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    window_size = struct.unpack('! H', data[14:16])[0]
    urgent_pointer = struct.unpack('! H', data[16:18])[0]
    decoded_payload = ""
    tcp_segment = IP(data[offset:])
    if Raw in tcp_segment:
        decoded_payload = str(tcp_segment[Raw].load)
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, urgent_pointer, decoded_payload, offset

#Log file for TCP packets
def log_tcp_packet(src, src_port, target, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, urgent_pointer, count):
    """
    Log TCP packet information to a log file.
    """
    now = datetime.now()
    with open(log_file_tcp, 'a') as log_file:
        log_file.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')}, {src}, {src_port}, {target}, {dest_port}, "
                       f"{sequence}, {acknowledgment}, {flag_urg}, {flag_ack}, {flag_psh}, {flag_rst}, {flag_syn}, {flag_fin}, "
                       f"{window_size}, {urgent_pointer}, {count}\n")
        log_file.close()


def detect_land_attack(src, target, log_file_tcp):
    if src == target:
        with open(log_file_tcp, 'a') as log_file:
            log_file.write(f"Land attack detected from {src} to {
                target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.close()
            return True

    return False        

# Detect SYN flood attack
def detect_syn_flood(src_ip):
    """
    Detect SYN flood attack by monitoring incoming SYN packets per source IP.
    If the count of SYN packets from a single IP exceeds the threshold within
    a specified time window, log the attack.
    """
    global syn_counts
    current_time = datetime.now()
    if src_ip not in syn_counts:
        syn_counts[src_ip] = [(current_time, 1)]
    else:
        syn_counts[src_ip].append((current_time, syn_counts[src_ip][-1][1] + 1))

    syn_counts[src_ip] = [syn_count for syn_count in syn_counts[src_ip] if current_time - syn_count[0] <= TIME_WINDOW]

    # Check if the SYN packet count exceeds the threshold within the specified time window
    if len(syn_counts[src_ip]) > SYN_FLOOD_THRESHOLD:
        attack_duration = (syn_counts[src_ip][-1][0] - syn_counts[src_ip][0][0]).total_seconds()
        packet_rate = syn_counts[src_ip][-1][1] / attack_duration
        if packet_rate > SYN_FLOOD_PACKET_RATE_THRESHOLD:
            return True

    # Remove old SYN packets
    syn_counts[src_ip] = [syn_count for syn_count in syn_counts[src_ip] if current_time - syn_count[0] <= TIME_WINDOW]

    return False

#TCP Window Size Manipulation
def detect_tcp_window_manipulation(window_size):
    """
    Detects TCP window manipulation attacks by checking if the TCP window size
    is less than or equal to zero.
    """
    if window_size <= 0:
        return True
    else:
        return False
    
# Detect TCP Fragmentation Attack
def detect_tcp_fragmentation_attack(offset, window_size, payload_length, payload):
    """
    Detects TCP fragmentation attacks by analyzing the TCP packet attributes.

    Args:
        offset (int): TCP packet offset
        window_size (int): TCP window size
        payload_length (int): TCP payload length
        payload (bytes): TCP payload

    Returns:
        bool: True if the packet is a TCP fragmentation attack, False otherwise
    """
    # Check if the packet is fragmented based on offset and payload length
    # If the packet is fragmented, return True
    if offset > 0 or payload_length < window_size or window_size <= 8:
        return True

    # Check for unusual window sizes
    # If the window size is less than or equal to 100 bytes, return True
    if window_size <= 100:
        return True

    # Check for unusual offsets
    # If the offset is not 0 or 8, return True
    if offset != 0 and offset != 8:
        return True

    # Check for payload length greater than 1400 bytes
    # If the payload length is greater than 1400 bytes, return True
    if payload_length > 1400:
        return True

    # Check for payload length greater than 500 bytes
    # If the payload length is greater than 500 bytes, return True
    if payload_length > 500:
        return True

    # Check for non-zero payload in the first or last 4 bytes
    # If the payload has non-zero data in the first or last 4 bytes, return True
    if payload[:4] != b'\x00' * 4 and payload[-4:] != b'\x00' * 4:
        return True

    # Check for the presence of a null byte in the payload
    # If the payload contains a null byte, return True
    if b'\x00' in payload:
        return True

    # If none of the above conditions are met, return False
    return False

def detect_tcp_injection_attack(src, src_port, target, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, urgent_pointer, decoded_payload):
    """
    Detects advanced TCP injection attacks by analyzing TCP packet attributes and payload.
    """
    # Check if PSH flag is set and there's data in the payload
    if flag_psh and decoded_payload:
        # Check for predictable sequence number (divisible by 100)
        if sequence % 100 == 0 and is_payload_sequential(decoded_payload) and is_payload_length_suspicious(len(decoded_payload)) and is_payload_encoding_suspicious(decoded_payload):
            print("[##] Advanced TCP Injection Attack Detected!")
            print(f"    - Source IP: {src}, Source Port: {src_port}")
            print(f"    - Destination IP: {target}, Destination Port: {dest_port}")
            print(f"    - Sequence: {sequence}, Acknowledgment: {acknowledgment}")
            print(f"    - Flags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
            print(f"    - Window Size: {window_size}, Urgent Pointer: {urgent_pointer}")
            
            # Analyze payload for suspicious patterns
            print("[##] Analyzing Payload:")
            analyze_payload(decoded_payload)
            print("\n")

def is_payload_sequential(decoded_payload):
    """
    Checks if the payload is sequential.
    """
    return all(ord(c) == i for i, c in enumerate(decoded_payload))

def is_payload_length_suspicious(length):
    """
    Checks if the payload length is suspicious.
    """
    return length > 1000 and length < 10000

def is_payload_encoding_suspicious(decoded_payload):
    """
    Checks if the payload encoding is suspicious.
    """
    return any(char in decoded_payload for char in [b'\x00', b'\x01', b'\xfe', b'\xff'])

def analyze_payload(decoded_payload):
    """
    Analyzes the payload for suspicious patterns indicating an advanced TCP injection attack.
    """
    # Check for common injection keywords
    for keyword in injection_keywords:
        if keyword.lower() in decoded_payload.lower():
            print(f"    - Detected potential SQL injection keyword: {keyword}")
    
    # Check for unexpected characters or encoding
    non_ascii_chars = [char for char in decoded_payload if ord(char) > 127]
    if non_ascii_chars:
        print("    - Detected non-ASCII characters in payload:")
        for char in non_ascii_chars:
            print(f"      - Character: {char}, ASCII Code: {ord(char)}")

    # Check for suspicious content length
    content_length = len(decoded_payload)
    if content_length > 10000:
        print(f"    - Suspiciously long payload length: {content_length} bytes")

    # Check for suspicious patterns in payload
    analyze_suspicious_patterns(decoded_payload)

def analyze_suspicious_patterns(decoded_payload):
    """
    Analyzes the payload for extreme level suspicious patterns.
    """
    # Check for presence of shellcode
    if any(pattern in decoded_payload for pattern in [b'MZ', b'\xeb\xfe']):
        print("[!!] Detected potential shellcode in payload")

    # Check for executable file signatures
    if any(decoded_payload.startswith(sig) for sig in [b'\x7f\x45\x4c\x46', b'\x4d\x5a\x90\x00\x03\x00']):
        print("[!!] Detected potential executable file signature")

    # Check for encoded or obfuscated payloads
    if any(keyword in decoded_payload.lower() for keyword in ['eval(', 'base64', 'encode', 'decode', 'gzip', 'bzip', 'compress', 'encrypt', 'decrypt', 'crypt', 'reverse', 'obfuscated', 'encoded', 'encryption', 'decryption', 'encrypt', 'decrypt', 'cipher', 'crypto', 'hash', 'mac', 'key', 'private', 'public', 'certificate', 'cert', 'pem', 'der', 'pkcs', 'ssl', 'tls', 'xor', 'rot', 'bit', 'shift', 'aes', 'des', 'rc4', 'blowfish', 'cast', 'twofish', 'arcfour', 'seed', 'tea', 'serpent', 'idea', 'rc2', 'rc5', 'rc6', 'salsa', 'camellia', 'rijndael', 'desx', 'skinny', 'act', 'speck', 'simon', 'khazad', 'lightweight', 'ecb', 'cbc', 'ctr', 'cfb', 'ofb', 'gcm', 'ccm', 'ocb', 'xts', 'wrap', 'unwrap', 'pkcs1', 'pkcs5', 'pkcs7', 'pkcs8', 'pkcs12', 'pkcs11', 'pkcs15', 'pkcs16', 'pkcs20', 'pkcs21', 'pkcs22', 'pkcs23', 'pkcs24', 'pkcs25', 'pkcs26', 'pkcs27', 'pkcs28', 'pkcs29', 'pkcs30', 'pkcs31', 'pkcs32', 'pkcs33', 'pkcs34', 'pkcs35', 'pkcs36', 'pkcs37', 'pkcs38', 'pkcs39', 'pkcs40', 'pkcs41', 'pkcs42', 'pkcs43', 'pkcs44', 'pkcs45', 'pkcs46', 'pkcs47', 'pkcs48', 'pkcs49', 'pkcs50', 'pkcs51', 'pkcs52', 'pkcs53', 'pkcs54', 'pkcs55', 'pkcs56', 'pkcs57', 'pkcs58', 'pkcs59', 'pkcs60', 'pkcs61', 'pkcs62', 'pkcs63', 'pkcs64', 'pkcs65', 'pkcs66', 'pkcs67', 'pkcs68', 'pkcs69', 'pkcs70', 'pkcs71', 'pkcs72', 'pkcs73', 'pkcs74', 'pkcs75', 'pkcs76', 'pkcs77', 'pkcs78', 'pkcs79', 'pkcs80', 'pkcs81', 'pkcs82', 'pkcs83', 'pkcs84', 'pkcs85', 'pkcs86', 'pkcs87', 'pkcs88', 'pkcs89', 'pkcs90', 'pkcs91', 'pkcs92', 'pkcs93', 'pkcs94', 'pkcs95', 'pkcs96', 'pkcs97', 'pkcs98', 'pkcs99', 'pkcs100', 'pkcs101', 'pkcs102', 'pkcs103', 'pkcs104', 'pkcs105', 'pkcs106', 'pkcs107', 'pkcs108', 'pkcs109', 'pkcs110', 'pkcs111', 'pkcs1']):
        print("[!!] Detected encoded or obfuscated payload")

# Detect TCP RESET ATTACK
def detect_tcp_reset_attack(ack, psh, rst, syn, fin, count, threshold, log_file):
    """
    Detects TCP Reset Attack by checking the TCP flags and ping count.

    Args:
        ack (bool): Acknowledgment flag
        psh (bool): Push flag
        rst (bool): Reset flag
        syn (bool): Synchronize flag
        fin (bool): Finish flag
        ping_count (int): Number of pings received
        threshold (int): Threshold for ping count

    Returns:
        bool: True if TCP Reset Attack is detected, False otherwise
    """
    if rst == 1 and ack == 0 and psh == 0 and fin == 0:
        with open(log_file, 'r') as file:
            count = sum(1 for line in file)
            if count >= threshold:
                return True
    return False 

def detect_tcp_syn_and_ack_attack(ack, psh, rst, syn, fin, count, threshold, log_file):
    """
    Detects TCP SYN and ACK Attack by checking the TCP flags and ping count.

    Args:
        ack (bool): Acknowledgment flag
        psh (bool): Push flag
        rst (bool): Reset flag
        syn (bool): Synchronize flag
        fin (bool): Finish flag
        ping_count (int): Number of pings received
        threshold (int): Threshold for ping count

    Returns:
        bool: True if TCP SYN and ACK Attack is detected, False otherwise
    """
    if (rst == 1 and syn == 1) and (ack == 0 and psh == 0 and fin == 0):
        with open(log_file, 'r') as file:
            count = sum(1 for line in file)
            if count >= threshold:
                return True
    return False        

#TCP Session Hijacking
def detect_tcp_session_hijacking(src_ip, src_port, target_ip, dest_port, sequence, flag_ack, flag_psh, flag_rst, flag_syn, payload, acknowledgment, log_file, flag_urg, flag_fin, window_size, urgent_pointer):
    """
    Detects TCP session hijacking by analyzing TCP packet attributes and payload.
    This function performs a sophisticated analysis on the packet to detect
    malicious activity at an extreme level.

    Args:
        src_ip (str): Source IP address
        src_port (int): Source port number
        target_ip (str): Destination IP address
        dest_port (int): Destination port number
        sequence (int): TCP sequence number
        acknowledgment (int): TCP acknowledgment number
        flags (dict): Dictionary containing TCP flags
        payload (bytes): TCP payload

    Returns:
        bool: True if TCP session hijacking is detected, False otherwise
    """
    # Check for unusual payload length
    if len(payload) > 1000:
        return True

    # Check for unusual sequence numbers
    if sequence < 1000 or sequence > 1000000:
        return True

    # Check for unexpected payload content
    # Analyze payload for known patterns or keywords indicating malicious activity
    for pattern in MALICIOUS_PATTERNS:
        if pattern in payload.lower():
            return True

    # Check for shellcode or code injection attempts in payload
    if contains_shellcode(payload):
        return True

    # Check for unusual encoding or obfuscation in payload
    if is_payload_encoded(payload) or is_payload_obfuscated(payload):
        return True

    # Check for unusual flag combination
    if flag_syn == 1 and flag_ack == 1 and flag_rst == 0 and flag_psh == 0:
        return True

    # Check for suspicious IP addresses
    if is_suspicious_ip(src_ip) or is_suspicious_ip(target_ip):
        return True

    # Check for suspicious hostnames
    if is_suspicious_hostname(src_ip) or is_suspicious_hostname(target_ip):
        return True

    # Check for suspicious port numbers
    if src_port in SUSPICIOUS_PORTS or dest_port in SUSPICIOUS_PORTS:
        return True

    # Check for unusual ACK numbers
    if acknowledgment < sequence - 1000 or acknowledgment > sequence + 1000:
        return True

    # Check for unusual window sizes
    if window_size < 100 or window_size > 10000:
        return True

    # Check for unusual flags combinations
    if (flag_syn == 1 and flag_ack == 0 and flag_rst == 0 and flag_psh == 0 and flag_fin == 0) or \
       (flag_syn == 0 and flag_ack == 1 and flag_rst == 0 and flag_psh == 0 and flag_fin == 0) or \
       (flag_syn == 0 and flag_ack == 0 and flag_rst == 1 and flag_psh == 0 and flag_fin == 0) or \
       (flag_syn == 0 and flag_ack == 0 and flag_rst == 0 and flag_psh == 1 and flag_fin == 0):
        return True

    # If none of the above conditions are met, return False (no hijacking detected)
    return False

def contains_shellcode(payload):
    """
    Checks if the payload contains shellcode or code injection attempt.
    This function performs a thorough analysis of the payload to detect
    shellcode or code injection attempts.
    """
    # Example: Check for common shellcode signatures or injection patterns
    shellcode_signatures = [b'MZ', b'\xeb\xfe']
    for signature in shellcode_signatures:
        if signature in payload:
            return True
    return False

def is_payload_encoded(payload):
    """
    Checks if the payload is encoded or encrypted.
    This function performs a more sophisticated analysis of the payload to detect
    encoding or encryption.
    """
    # Example: Check for common encoding indicators in payload
    encoding_indicators = [b'base64', b'encrypt', b'decrypt', b'gzip', b'bzip', b'encode', b'decode']
    for indicator in encoding_indicators:
        if indicator in payload.lower():
            return True
    return False

def is_payload_obfuscated(payload):
    """
    Checks if the payload is obfuscated or contains suspicious obfuscation patterns.
    This function performs a thorough analysis of the payload to detect
    obfuscation or suspicious obfuscation patterns.
    """
    # Example: Check for common obfuscation techniques or suspicious patterns
    obfuscation_patterns = [b'xor', b'rot', b'bitshift', b'obfuscated', b'encoded']
    for pattern in obfuscation_patterns:
        if pattern in payload.lower():
            return True
    return False

def is_suspicious_ip(ip):
    """
    Checks if the IP address is suspicious.
    This function performs a lookup in a blacklist of known malicious IP addresses.
    """
    with open('blacklist.txt', 'r') as f:
        blacklist = f.read().splitlines()
    return ip in blacklist

def is_suspicious_hostname(ip):
    """
    Checks if the hostname associated with the IP address is suspicious.
    This function performs a reverse DNS lookup and checks if the hostname
    matches common malicious patterns.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname.endswith('.ru') or hostname.endswith('.cn') or hostname.endswith('.com.cn'):
            return True
    except socket.herror:
        pass
    return False

SUSPICIOUS_PORTS = [22, 23, 25, 53, 80, 443, 3389, 5900]

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

def http_segment(data):
    request_method = data[:data.find(b' ')]
    url = data[data.find(b' ')+1:data.find(b'HTTP/')]
    http_version = data[data.find(b'HTTP/')+5:data.find(b'\r\n')]
    end_of_headers = data.find(b'\r\n\r\n')
    headers = data[len(request_method) + len(b' ') + len(url) + len(b' ') + len(b'HTTP/') + len(http_version) + len(b'\r\n'):end_of_headers]
    payload = data[end_of_headers + len(b'\r\n\r\n'):]
    decoded_payload = payload.decode('iso-8859-1')
    return request_method.decode('iso-8859-1'), url.decode('iso-8859-1'), http_version.decode('iso-8859-1'), headers.decode('iso-8859-1'), decoded_payload

def detect_xss(payload):
    decoded_payload = unquote_payload(payload)
    xss_patterns = load_xss_patterns()

    for pattern in xss_patterns:
        if pattern.search(decoded_payload):
            return True
    
    return False

def unquote_payload(payload, num_iterations=2):
    decoded_payload = payload
    for _ in range(num_iterations):
        decoded_payload = unquote(decoded_payload)
    return decoded_payload

def load_xss_patterns():
    with open(XSS_PAYLOADS_FILE, 'r') as f:
        xss_payloads = f.read().splitlines()
    
    patterns = []
    for payload in xss_payloads:
        pattern = re.compile(re.escape(payload), re.IGNORECASE)
        patterns.append(pattern)
    
    # Add common XSS patterns
    common_patterns = [
        re.compile(r"<script.?>.?</script>", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"vbscript:", re.IGNORECASE),
        re.compile(r"expression\(", re.IGNORECASE),
        re.compile(r"src\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
        re.compile(r"href\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
    ]
    patterns.extend(common_patterns)
    
    return patterns

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

def log_xss_payload(payload):
    with open("xss_detected.log", "a") as f:
        f.write(f"XSS Detected: {payload}\n")

if __name__ == '__main__':
    main()
