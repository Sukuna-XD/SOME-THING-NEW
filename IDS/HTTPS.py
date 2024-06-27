import struct
# HTTPS unpack
def https_packet(data):
    """
    Enhanced unpacking of HTTPS packets.
    Unpacks HTTPS packets and returns all fields similar to wireshark.
    """
    fields = '! H H L L H'  # b - 1 byte, H - 2 bytes, L - 4 bytes
    unpacked_data = struct.unpack(fields, data[:14])
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = unpacked_data
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 63
    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1
    window_size = struct.unpack('! H', data[14:16])[0]
    checksum = struct.unpack('! H', data[16:18])[0]
    urgent_pointer = struct.unpack('! H', data[18:20])[0]
    payload = data[20 + offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, checksum, urgent_pointer, payload
