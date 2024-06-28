import struct
#SMTP response codes
SMTP_RESPONSE_CODES = {
    '250': ['OK'],
    '550': ['Mailbox unavailable'],
    '553': ['Mailbox name not allowed'],
    '554': ['Transaction failed'],
    '421': ['Service not available'],
    '500': ['Syntax error'],
    '501': ['Syntax error'],
    '502': ['Syntax error'],
    '503': ['Syntax error'],
    '504': ['Syntax error'],
    '505': ['Syntax error'],
    '530': ['Authentication required'],
    '535': ['Authentication failed'],
    '550': ['Mailbox unavailable'],
    '553': ['Mailbox name not allowed'],
    '554': ['Transaction failed']
}

# Dictionary for mapping SMTP command codes to their names
SMTP_COMMANDS = {
    0x00: 'HELO',
    0x01: 'EHLO',
    0x02: 'MAIL FROM',
    0x03: 'RCPT TO',
    0x04: 'DATA',
    0x05: 'RSET',
    0x06: 'QUIT',
    0x07: 'NOOP',
    0x08: 'VRFY',
    0x09: 'EXPN',
    0x0A: 'HELP',
    0x0B: 'TURN',
    0x0C: 'STARTTLS'
}

# Unpack SMTP packets
def smtp_packet(data):
    """
    Unpacks SMTP packets and returns all fields.
    """
    fields = '! I B B'  # B - 1 byte, I - 4 bytes
    unpacked_data = struct.unpack(fields, data[:6])
    command_code, major_version, minor_version = unpacked_data
    command = SMTP_COMMANDS.get(command_code, 'Unknown')
    response_code = None
    response_text = None
    parameters = []
    payload = data[5:]

    if payload:
        # Parse the parameters
        parts = payload.split(b' ')
        response_code = parts[0].decode('utf-8', 'ignore')
        if len(parts) > 1:
            response_text = parts[1].decode('utf-8', 'ignore')
            parameters = [part.decode('utf-8', 'ignore') for part in parts[2:]]

    return command, major_version, minor_version, response_code, response_text, parameters, payload


# smtp rules
def smtp_rules(data):
    fields = '! I B B'  # B - 1 byte, I - 4 bytes
    unpacked_data = struct.unpack(fields, data[:6])
    command_code, major_version, minor_version = unpacked_data
    
    if command_code not in SMTP_COMMANDS.values():
        return True  # invalid command code
    
    if len(data) < 6:
        return True  # packet too short
    
    payload = data[5:]
    if payload:
        # Parse the parameters
        parts = payload.split(b' ')
        response_code = parts[0].decode('utf-8', 'ignore')
        if len(parts) > 1:
            response_text = parts[1].decode('utf-8', 'ignore')
            parameters = [part.decode('utf-8', 'ignore') for part in parts[2:]]
        
        if response_code not in SMTP_RESPONSE_CODES:
            return True  # invalid response code
        
        if response_text and response_text not in SMTP_RESPONSE_CODES[response_code]:
            return True  # invalid response text
    
    return False  # no malicious traffic detected