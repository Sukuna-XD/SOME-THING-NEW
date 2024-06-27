
            elif proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload) = tcp_segment(data)

                # HTTPS
                if dest_port == 433 or src_port == 443:
                    (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window_size, checksum, urgent_pointer, payload) = https_packet(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTPS {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + f"   - Source Port: {src_port}, Destination Port: {dest_port}".format(src_port, dest_port))
                    print(TAB_3 + f"   - Sequence: {sequence}, Acknowledgment: {acknowledgment}".format(sequence, acknowledgment))
                    print(TAB_3 + f"   - Checksum: {checksum}".format(checksum))
                    print(TAB_3 + f"   - Urgent Pointer: {urgent_pointer}".format(urgent_pointer))
                    print(TAB_3 + f"   - Window Size: {window_size}".format(window_size))
                    print(TAB_2 + ' - Flags:')
                    print(TAB_4 + f"     - URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}".format(flag_urg, flag_ack,
                                                                                                flag_psh, flag_rst,
                                                                                                flag_syn, flag_fin))
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload))


                # HTTP Packet
                elif dest_port == 80 or src_port == 80:
                    (src_port, dest_port, req_line, headers, payload, content_length) = http_packet(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + f"   - Source Port: {src_port}, Destination Port: {dest_port}".format(src_port, dest_port))
                    print(TAB_3 + f"   - Sequence: {sequence}, Acknowledgment: {acknowledgment}".format(sequence, acknowledgment))
                    print(TAB_3 + f"  - Version: {version}")
                    print(TAB_3 + f"Content Length: {content_length}")
                    print(TAB_3 + f"  - Request-Line: {req_line}")
                    print(TAB_3 + f"- Headers: {headers}")
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload))
                
                
                #DNS    
                elif dest_port == 53 or src_port == 53:
                    (id, flags, num_questions, num_answers, query, answer, payload) = dns_packet(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DNS {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + '   - Source Port: {src_port}, Destination Port: {dest_port}'.format(src_port, dest_port))
                    print(TAB_3 + '   - Sequence: {sequence}, Acknowledgment: {acknowledgment}'.format(sequence, acknowledgment))
                    print(TAB_3 + '   - ID: {id}, Flags: {flags}'.format(id, flags))
                    print(TAB_3 + '   - Number of Questions: {num_questions}, Number of Answers: {num_answers}'.format(num_questions, num_answers))
                    print(TAB_3 + '   - Query: {query}'.format(query))
                    print(TAB_3 + '   - Answer: {answer}'.format(answer))
                    print(TAB_3 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload))
                
                # For SMTP
                elif dest_port == 25 or src_port == 25:
                    (command, major_version, minor_version, response_code, response_text, parameters) = smtp_packet(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SMTP {src}:{src_port} ==> {target}:{dest_port}")
                    print(TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}")
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + '   - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_3 + '   - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_3 + '   - Command: {}, Major Version: {}, Minor Version: {}'.format(command, major_version, minor_version))
                    print(TAB_3 + '   - Response Code: {}, Response Text: {}'.format(response_code, response_text))
                    print(TAB_3 + '   - Parameters: {}'.format(parameters))

            elif proto == 17:
                # UDP Packet
                (src_port, dest_port, length, checksum, payload) = udp_segment(data)
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] UDP {src}:{src_port} ==> {target}:{dest_port}")
                print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                print(TAB_2 + ' - UDP Segment:')
                print(TAB_3 + '   - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_3 + '   - Length: {}'.format(length))
                print(TAB_3 + '   - Payload:')
                print(format_multi_line(DATA_TAB_3, data))
                # DNS
                if dest_port or src_port == 53:
                    (id, flags, num_questions, num_answers, query, answer, payload) = dns_packet(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DNS {src}:{src_port} ==> {target}:{dest_port}")
                    print (TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}".format(src_mac, dest_mac))
                    print(TAB_2 + ' - UDP Segment:')
                    print(TAB_3 + '   - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_3 + '   - Length: {}'.format(length))
                    print(TAB_3 + '   - Number of Questions: {}, Number of Answers: {}'.format(num_questions, num_answers))
                    print(TAB_3 + '   - Query: {}'.format(query))
                    print(TAB_3 + '   - Answer: {}'.format(answer))
                    print(TAB_3 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, payload)) 