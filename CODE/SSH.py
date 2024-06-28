import struct

SSH_PACKET_TYPES = {
    1: 'SSH_MSG_DISCONNECT',
    2: 'SSH_MSG_IGNORE',
    3: 'SSH_MSG_UNIMPLEMENTED',
    4: 'SSH_MSG_DEBUG',
    5: 'SSH_MSG_SERVICE_REQUEST',
    6: 'SSH_MSG_SERVICE_ACCEPT',
    20: 'SSH_MSG_KEXINIT',
    21: 'SSH_MSG_NEWKEYS',
    30: 'SSH_MSG_KEXDH_INIT',
    31: 'SSH_MSG_KEXDH_REPLY',
    50: 'SSH_MSG_USERAUTH_REQUEST',
    51: 'SSH_MSG_USERAUTH_FAILURE',
    52: 'SSH_MSG_USERAUTH_SUCCESS',
    53: 'SSH_MSG_USERAUTH_BANNER',
    60: 'SSH_MSG_USERAUTH_INFO_REQUEST',
    61: 'SSH_MSG_USERAUTH_INFO_RESPONSE',
    80: 'SSH_MSG_GLOBAL_REQUEST',
    81: 'SSH_MSG_REQUEST_SUCCESS',
    82: 'SSH_MSG_REQUEST_FAILURE'
}

def ssh_packet(data):
    """
    Enhanced unpacking of SSH packets.
    Unpacks SSH packets and returns all fields.
    """
    fields = '! B B I I'  # b - 1 byte, I - 4 bytes
    unpacked_data = struct.unpack(fields, data[:9])
    src_port, dest_port, length = unpacked_data
    sequence = struct.unpack('! I', data[9:13])[0]
    payload = data[13:13 + length]

    packet_type = int(payload[0])
    packet_type_name = SSH_PACKET_TYPES.get(packet_type, 'Unknown')
    packet_padding_length = int(payload[1])
    packet_payload = payload[2:-packet_padding_length - 1]

    return src_port, dest_port, sequence, length, packet_type, packet_type_name, packet_padding_length, packet_payload

def ssh_rules(src_port, dest_port, sequence, length, packet_type, packet_type_name, packet_padding_length, packet_payload):
    """
    Implement different rules for SSH packets.
    """
    if src_port == 22 and dest_port == 22 and packet_type not in (1, 2, 3, 4, 6, 20, 21, 30, 31, 50, 51, 52, 53, 60, 61, 80, 81, 82):
        return True  # SSH traffic detected
    return False


