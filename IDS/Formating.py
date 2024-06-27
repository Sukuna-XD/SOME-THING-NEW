import textwrap

TAB_1 = '    '
TAB_2 = '        '
TAB_3 = '            '
TAB_4 = '                '

DATA_TAB_1 = '        '
DATA_TAB_2 = '            '
DATA_TAB_3 = '                '
DATA_TAB_4 = '                    '

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

# format the multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    elif isinstance(string, int):
        string = str(string)  # Convert integer to string
    else:
        string = str(string)  # Convert other types to string
    
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

