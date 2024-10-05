from .usefull import *
import struct

#DNS ---https://tools.ietf.org/html/rfc2929

def dns(data_3, udp_size, newObject):
    dns_rcodes = {'0': 'No error(0)', '1': 'Format error(1)', '2': 'Server failure(2)', '3': 'Name Error(3)',
                  '4': 'Not Implemented(4)', '5': 'Refused(5)'}
    dns_opcodes = {'0': 'Standard query(0)', '1': 'Inverse query(1)', '2': 'Server status request(2)'}
    dns_query_types = {'1': 'host address  ', '2': 'authoritative nameserver ', '3': '[mail_destination][3]',
                       '4': '[mail_forwarder][4]', '5': 'canonical name for an alias[CNAME][5]',
                       '6': 'Start of zone of authority ', '7': '[mailbox_domain_name][7]',
                       '8': '[mail_group_member][8]', '9': '[mail_rename_domain_name][9]',
                       '10': '', '15': 'mail exchange ',
                       '16': 'text string ', '24': 'security signature ',
                       '28': 'IPv6 Address ', '33': ' '}
    dns_query_classes = {'1': 'Internet ', '3': 'Chaos ', '4': 'Hesiod '}

    if show_dns != 0:
        id, flags_codes, query_c, answ_c, auth_c, addi_c = struct.unpack("!HHHHHH", data_3[:12])
        opcode = (flags_codes >> 11) & 15
        Response = "Response:Response(1)" if is_bit_set(flags_codes, 1, 16) else "Response:Query(0)"
        OpCode = f"OpCode: {dns_opcodes.get(str(opcode), 'Unknown')}"

        Authoritative = "Authoritative:Authoritative_Server(1)" if is_bit_set(flags_codes, 6, 16) else "Authoritative:Non-authoritative_Server(0)"
        Truncated = "Truncated:Truncated(1)" if is_bit_set(flags_codes, 7, 16) else "Truncated:Non-Truncated(0)"
        Recursion = "Recursion:query_recursively(1)" if is_bit_set(flags_codes, 8, 16) else "Recursion:query_Non-recursively(0)"
        AvailRecursion = "Recursion_available:Recursive_queries_possible(1)" if is_bit_set(flags_codes, 9, 16) else "Recursion_available:Recursive_queries_not_possible(0)"
        Z = "Z:not_reserved(1)" if is_bit_set(flags_codes, 10, 16) else "Z:reserved(0)"
        AnsAuth = "Answer_authenticated:authenticated(1)" if is_bit_set(flags_codes, 11, 16) else "Answer_authenticated:Non-authenticated(0)"
        NonAuth = "Non-authenticated_data:Acceptable(1)" if is_bit_set(flags_codes, 12, 16) else "Non-authenticated_data:Unacceptable(0)"

        rcode = flags_codes & 15
        queries, answers, auth_answers, addi_answers = '', '', '', ''

        qname, index = get_dns_name(data_3, 12)
        qtype, qclass = struct.unpack("!HH", data_3[index:index + 4])
        index += 4
        queries += f"\tQueries: Name: {qname} Type: {dns_query_types.get(str(qtype), 'Unknown')} Class: {dns_query_classes.get(str(qclass), 'Unknown')}\n"

        if answ_c != 0:
            answers += "\tAnswers:-\n"
        for i in range(answ_c):
            req_index = ord(struct.unpack("!s", data_3[index + 1])[0])
            index += 2
            a_type, a_class, a_ttl, a_len = struct.unpack("!HHIH", data_3[index:index + 10])
            index += 10
            rdata = get_dns_data(data_3, index, a_type)
            index += a_len
            a_name, _ = get_dns_name(data_3, req_index)
            answers += f"\t(*){i + 1}: Name: {a_name} Type: {dns_query_types.get(str(a_type), 'Unknown')} Class: {dns_query_classes.get(str(a_class), 'Unknown')} Time_to_live: {a_ttl} Data_length: {a_len} {rdata}\n"

        newObject.setDNS(Response, OpCode, Authoritative, Truncated, Recursion, AvailRecursion, Z, AnsAuth, NonAuth,
                         f" Transaction_ID:0x{id:x}", f" Reply_code: {dns_rcodes.get(str(rcode), 'Unknown')}",
                         f"Queries_count: {query_c}", f"Answers_count: {answ_c}", f"Authority_count: {auth_c}",
                         f"Additional_info_count: {addi_c}", queries, answers, auth_answers, addi_answers)


def get_dns_data(data_3, index, dns_type):
    if dns_type == 1:  # A
        addr = ipv4(struct.unpack("!4s", data_3[index:index + 4])[0])
        rdata = f"A address: {addr}"
    elif dns_type == 2:  # NS
        name, _ = get_domain_name(data_3, index)
        rdata = f"Name Server: {name}"
    elif dns_type == 5:  # CNAME
        name, _ = get_domain_name(data_3, index)
        rdata = f"CNAME: {name}"
    elif dns_type == 28:  # AAAA
        addr = ipv6(struct.unpack("!16s", data_3[index:index + 16])[0])
        rdata = f"AAAA address: {addr}"
    else:
        rdata = "rdata: Not implemented yet....!!!"
    return rdata


def get_domain_name(data_3, index):
    check, req = struct.unpack("!s", data_3[index]), struct.unpack("!s", data_3[index + 1])
    a_name = ""
    prev_check = check
    check = ord(check[0])
    check = (check >> 6) << 6

    is_null_bit = 1
    if prev_check[0] != b'\x00':
        if check != ord('\xc0'):
            a_name, index = get_dns_name(data_3, index)
            check = struct.unpack("!s", data_3[index])[0]
            check = ord(check)
            check = (check >> 6) << 6
            is_null_bit = ord(struct.unpack("!s", data_3[index - 1])[0])
        if check == ord('\xc0') and is_null_bit != 0:
            index += 1
            req_index = struct.unpack("!H", data_3[index])[0]
            req_name, _ = get_domain_name(data_3, req_index)
            a_name += req_name
            index += 2
    else:
        a_name = '<Root>'
        index += 1
    return a_name, index


def get_dns_name(data_3, index):
    if index == 0:
        return "", index + 1
    char = struct.unpack("!s", data_3[index])
    qname = ""
    new_char = ord(char[0])
    new_char = (new_char >> 6) << 6

    while ord(char[0]) != 0 and new_char != ord('\xc0'):
        for i in range(ord(char[0])):
            index += 1
            char = struct.unpack("!s", data_3[index])
            qname += char[0].decode('utf-8')
        index += 1
        char = struct.unpack("!s", data_3[index])
        new_char = ord(char[0])
        new_char = (new_char >> 6) << 6
        qname += "."
    if new_char != ord('\xc0'):
        index += 1
    return qname, index
