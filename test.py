from scapy.all import *
import codecs
import binascii
import datetime

packet_data_raw = []
packet_data_hex = []
packet_num = 0
# 이더넷
Des_MAC_Adr=[]
Src_MAC_Adr=[]
IP_Type=[]
# IP
IP_Version=[]
IP_Header_Length=[]
TOS=[]
IP_Total_Length=[]
IP_ID=[]
Flag_Fragment_Offset=[]
TTL=[]
Protocol_Number=[]
Header_Checksum=[]
Src_IP=[]
Des_IP=[]
IP_Option=[]
# TCP
Sequence_Number=[]
ACK=[]
TCP_Header_Length=[]
Flag=[]
Window=[]
UrgentPointer=[]
TCP_Option=[]
# UDP
UDP_Length=[]
# ICMP
Type=[]
Code=[]
# Common
Src_Port=[]
Des_Port=[]
Payload=[]
Checksum=[]  # Payload = data[]
# ---function-----------------------------------------------------------------------------------------------------------------------------------------
def showpacket(packet):
    # packet[0][1]: ip, packet[0][2]: TCP, UDP, IP
    print("-----------------------------------------------------------------------------------------------------------------------------------------")
    print('RAW: {}->\nHEX: {}'.format(raw(packet), bytes_hex(packet))) #raw(packet) -> bytes_hex(packet)
    new_packet = codecs.encode(raw(packet), 'hex').decode('ascii')
    packet_data_hex.append(new_packet)
    analyze_RAW(new_packet)

def analyze_RAW(str_hex):
    # 이더넷 헤더
    raw_packet = str_hex  # 들어온 패킷 저장함. -> 디코딩
    print("hex: ", raw_packet)  # [a:b] = a <= ㅁ < b
    Des_MAC_Adr.append(raw_packet[ 0:12]), Src_MAC_Adr.append(raw_packet[12:24])
    print("Des MAC Adr: {}, Src MAC Adr: {}".format(raw_packet[ 0:12],raw_packet[12:24]))
    IP_Type.append(raw_packet[24:28])
    print("IP Type: ", raw_packet[24:28])  # 0800: IPv4
    # IP 헤더
    ip_header_length = 4 * int(raw_packet[29:30], 16)
    ip_total_length = int(raw_packet[32:36], 16)
    IP_Version.append(int(raw_packet[28:29],16)), IP_Header_Length.append(ip_header_length), TOS.append(int(raw_packet[30:32],16)), IP_Total_Length.append(ip_total_length)
    print("IP Version: {}, IP Header Length: {}, TOS: {}, IP Total Length: {}".format(int(raw_packet[28:29],16), ip_header_length, int(raw_packet[30:32],16), ip_total_length))
    IP_ID.append("0x"+raw_packet[36:40]), Flag_Fragment_Offset.append(raw_packet[40:44]), TTL.append(int(raw_packet[44:46],16))
    print("IP ID: 0x{}, Flag & Fragment Offset: {}, Time To Live: {}".format(raw_packet[36:40], raw_packet[40:44], int(raw_packet[44:46],16)))  # IP ID, 4*4 = 16 = 3:13 -> 보류, flag 3: 16진수 + offset 13: 10진수
    transfer_protocol = int(raw_packet[46:48],16)
    if transfer_protocol == 1:
        Protocol_Number.append("ICMP")
        print("Protocol: ICMP")
    elif transfer_protocol == 6:
        Protocol_Number.append("TCP")
        print("Protocol: TCP")
    elif transfer_protocol == 17:
        Protocol_Number.append("UDP")
        print("Protocol: UDP")
    else:
        Protocol_Number.append(str(transfer_protocol))  # str
        print("Protocol Number: ", transfer_protocol)
    Header_Checksum.append("0x"+raw_packet[48:52])
    print("Header Checksum: 0x", raw_packet[48:52])
    src_ip_adr = str(int(raw_packet[52:54],16))+"."+str(int(raw_packet[54:56],16))+"."+str(int(raw_packet[56:58],16))+"."+str(int(raw_packet[58:60],16))
    des_ip_adr = str(int(raw_packet[60:62],16))+"."+str(int(raw_packet[62:64],16))+"."+str(int(raw_packet[64:66],16))+"."+str(int(raw_packet[66:68],16))
    Src_IP.append(src_ip_adr), Des_IP.append(des_ip_adr)
    print("Src IP Adr: {}, Des IP Adr: {}".format(src_ip_adr,des_ip_adr))
    IP_Option.append(" "+raw_packet[68:28+2*ip_header_length])
    print("IP Option: {}".format(raw_packet[68:28+2*ip_header_length]))
    transfer_packet = raw_packet[28+2*ip_header_length: ]  # 자름
    if transfer_protocol == 1:
        analyze_ICMP(transfer_packet)
    elif transfer_protocol == 6:
        analyze_TCP(transfer_packet)
    elif transfer_protocol == 17:
        analyze_UDP(transfer_packet)
    else:
        print("Other Protocol: ", transfer_protocol)

def analyze_TCP(str_hex):
    # TCP
    tcp_input_packet = str_hex
    tcp_header_length = 4 * int(tcp_input_packet[24:25],16)
    if (int(tcp_input_packet[0:4],16) == 80 or int(tcp_input_packet[4:8], 16) == 80):
        Protocol_Number[len(Protocol_Number) - 1] = 'HTTP'
        print("HTTP Protocol")
    Src_Port.append(int(tcp_input_packet[0:4], 16)), Des_Port.append(int(tcp_input_packet[4:8], 16))
    print("Src Port: {}, Des Port: {}".format(int(tcp_input_packet[0:4], 16), int(tcp_input_packet[4:8], 16)))
    Sequence_Number.append(int(tcp_input_packet[8:16], 16)), ACK.append(int(tcp_input_packet[16:24], 16))
    print("Sequence Number: {}, ACK: {}".format(int(tcp_input_packet[8:16], 16), int(tcp_input_packet[16:24], 16)))  # ACK 확인용 넘버, ACK
    TCP_Header_Length.append(tcp_header_length), Flag.append("0x"+tcp_input_packet[25:28]), Window.append(int(tcp_input_packet[28:32], 16))
    print("TCP Header Length: {}, Flag: 0x{}, Window: {}".format(tcp_header_length, tcp_input_packet[25:28], int(tcp_input_packet[28:32], 16)))
    Checksum.append("0x"+tcp_input_packet[32:36]), UrgentPointer.append(int(tcp_input_packet[36:40],16))
    print("Checksum: 0x{}, UrgentPointer: {}".format(tcp_input_packet[32:36], int(tcp_input_packet[36:40],16)))
    TCP_Option.append(" "+tcp_input_packet[40:2*tcp_header_length])
    print("TCP Option: ", tcp_input_packet[40:2*tcp_header_length])
    Payload.append(binascii.unhexlify(tcp_input_packet[2*tcp_header_length: ]))  # snowCheck
    print("Payload: {}".format(binascii.unhexlify(tcp_input_packet[2*tcp_header_length: ])))
    UDP_Length.append(-1), Type.append(-1), Code.append(-1)

def analyze_UDP(str_hex):
    # UDP
    udp_input_packet = str_hex
    if(int(udp_input_packet[0:4],16) == 53 or int(udp_input_packet[4:8], 16) == 53):
        Protocol_Number[len(Protocol_Number) - 1] = 'DNS'
        print("DNS Protocol")
    Src_Port.append(int(udp_input_packet[0:4], 16)), Des_Port.append(int(udp_input_packet[4:8], 16))
    print("Src Port: {}, Des Port: {}".format(int(udp_input_packet[0:4], 16), int(udp_input_packet[4:8], 16)))
    UDP_Length.append(int(udp_input_packet[8:12], 16)), Checksum.append("0x"+udp_input_packet[12:16])
    print("UDP Length: {}, Checksum: 0x{}".format(int(udp_input_packet[8:12], 16), udp_input_packet[12:16]))  # 헤더는 8바이트
    Payload.append(binascii.unhexlify(udp_input_packet[16: ]))
    print("Data: {}".format(binascii.unhexlify(udp_input_packet[16: ])))
    Sequence_Number.append(-1), ACK.append(-1), TCP_Header_Length.append(-1), Flag.append('nil'), Window.append(-1), UrgentPointer.append(-1), TCP_Option.append('nil'), Type.append(-1), Code.append(-1)
def analyze_ICMP(str_hex):
    # ICMP
    icmp_input_packet = str_hex
    print("ICMP Protocol")
    Type.append(int((icmp_input_packet[0:2]), 16))
    type = int((icmp_input_packet[0:2]), 16)
    Code.append(int((icmp_input_packet[2:4]), 16))
    code = int((icmp_input_packet[2:4]), 16)
    print("Type: {} Code:{}".format(type, code))
    Checksum.append(icmp_input_packet[4:8])
    print("Checksum: 0x", icmp_input_packet[4:8])
    Payload.append(binascii.unhexlify(icmp_input_packet[8: ]))
    print("Data: {}".format(binascii.unhexlify(icmp_input_packet[8: ])))
    UDP_Length.append(-1), Sequence_Number.append(-1), ACK.append(-1), TCP_Header_Length.append(-1), Flag.append('nil'), Window.append(-1), UrgentPointer.append(-1), TCP_Option.append('nil')

    if(type == 8 and code == 0):
        print("echo request(ping)")
    elif(type == 0 and code == 0):
        print("echo reply(ping)")
    elif(type == 11 and code == 0):
        print("TTL expired")
    elif(type == 3 and code == 3):
        print("destination port unreachable")
    else:
        print("the other case")
# not function----------------------------------------------------------------------------------------------------------------------------------------
select_packets = int(input("캡처하실 패킷의 개수를 결정하세요. "))
if(select_packets < 0 ):
    print("개수는 음수가 될 수 없습니다.")
else:
    sniff(prn=showpacket, count=select_packets)
    print("캡쳐된 패킷수: "+str(len(Protocol_Number)))
print(Protocol_Number)
select_protocol = input("\n찾으시고 싶으신 프로토콜을 대문자로 입력하세요. (HTTP, DNS, ICMP, TCP, UDP) ")

protocol_tag = ['HTTP', 'DNS', 'ICMP', 'TCP', 'UDP']
check_input = -1
for tag in range(len(protocol_tag)):
    if(select_protocol==protocol_tag[tag]):
        check_input = 0

if(check_input == -1):
    print("잘못된 입력입니다. 프로그램을 종료합니다.")
else:
    with open(select_protocol+"_packet_data.txt", "a") as file:
        now = datetime.datetime.now()
        file.write("출력 시간: "+str(now)+'\n')
        for pro in range(len(Protocol_Number)):  # range: 숫자로, 없으면 그자체
            if(select_protocol == Protocol_Number[pro]):
                file.write("Des_MAC_Adr: "+Des_MAC_Adr[pro]+", Src_MAC_Adr: "+Src_MAC_Adr[pro]+", IP_Type: "+IP_Type[pro]+"\n")
                print("Des_MAC_Adr: {}, Src_MAC_Adr: {}, IP_Type: {}".format(Des_MAC_Adr[pro],Src_MAC_Adr[pro],IP_Type[pro]))
                file.write("IP_Version: "+str(IP_Version[pro])+", IP_Header_Length: "+str(IP_Header_Length[pro])+", TOS: "+str(TOS[pro])+", IP_Total_Length: "+str(IP_Total_Length[pro])+"\n")
                print("IP_Version: {}, IP_Header_Length: {}, TOS: {}, IP_Total_Length: {}".format(IP_Version[pro],IP_Header_Length[pro],TOS[pro],IP_Total_Length[pro]))
                file.write("IP_ID: "+IP_ID[pro]+", Flag_Fragment_Offset: "+Flag_Fragment_Offset[pro]+", TTL: "+str(TTL[pro])+", Protocol: "+Protocol_Number[pro]+", Header_Checksum: "+Header_Checksum[pro]+"\n")
                print("IP_ID: {}, Flag_Fragment_Offset: {}, TTL: {}, Protocol_Number: {}, Header_Checksum: {}".format(IP_ID[pro],Flag_Fragment_Offset[pro],TTL[pro],Protocol_Number[pro],Header_Checksum[pro]))
                file.write("Src_IP: "+Src_IP[pro]+", Des_IP: "+Des_IP[pro]+", IP_Option: "+IP_Option[pro]+"\n")
                print("Src_IP: {}, Des_IP: {}, IP_Option: {} ".format(Src_IP[pro],Des_IP[pro],IP_Option[pro]))
                if(select_protocol == 'HTTP'):
                    file.write("Src_Port: " + str(Src_Port[pro]) + ", Des_Port: " + str(Des_Port[pro]) + "\n")
                    print("Src Port: {}, Des Port: {}".format(Src_Port[pro], Des_Port[pro]))
                    file.write("Sequence_Number: " + str(Sequence_Number[pro]) + ", ACK: " + str(ACK[pro]) + "\n")
                    print("Sequence Number: {}, ACK: {}".format(Sequence_Number[pro], ACK[pro]))
                    file.write("TCP_Header_Length: " + str(TCP_Header_Length[pro]) + ", Flag: " + Flag[
                        pro] + ", Window: " + str(Window[pro]) + "\n")
                    print("TCP Header Length: {}, Flag: {}, Window: {}".format(TCP_Header_Length[pro], Flag[pro],Window[pro]))
                    file.write("Checksum: " + Checksum[pro] + ", UrgentPointer: " + str(UrgentPointer[pro]) + ", TCP_Option: " + TCP_Option[pro] + "\n")
                    print("Checksum: {}, UrgentPointer: {}, TCP Option: {}".format(Checksum[pro], UrgentPointer[pro],TCP_Option[pro]))
                    file.write("Payload: "+str(Payload[pro])+'\n\n')
                    print("Payload: {}".format(Payload[pro]))
                elif (select_protocol == 'TCP'):
                    file.write("Src_Port: "+str(Src_Port[pro])+", Des_Port: "+str(Des_Port[pro])+"\n")
                    print("Src Port: {}, Des Port: {}".format(Src_Port[pro],Des_Port[pro]))
                    file.write("Sequence_Number: "+str(Sequence_Number[pro])+", ACK: "+str(ACK[pro])+"\n")
                    print("Sequence Number: {}, ACK: {}".format(Sequence_Number[pro],ACK[pro]))
                    file.write("TCP_Header_Length: "+str(TCP_Header_Length[pro])+", Flag: "+Flag[pro]+", Window: "+str(Window[pro])+"\n")
                    print("TCP Header Length: {}, Flag: {}, Window: {}".format(TCP_Header_Length[pro],Flag[pro],Window[pro]))
                    file.write("Checksum: "+Checksum[pro]+", UrgentPointer: "+str(UrgentPointer[pro])+", TCP_Option: "+TCP_Option[pro]+"\n")
                    print("Checksum: {}, UrgentPointer: {}, TCP Option: {}".format(Checksum[pro],UrgentPointer[pro],TCP_Option[pro]))
                    file.write("Payload: "+str(Payload[pro])+'\n\n')
                    print("Payload: {}".format(Payload[pro]))
                elif(select_protocol == 'DNS'):
                    file.write("Src_Port: " + str(Src_Port[pro]) + ", Des_Port: " + str(Des_Port[pro]) + "\n")
                    print("Src Port: {}, Des Port: {}".format(Src_Port[pro], Des_Port[pro]))
                    file.write("UDP_Length: "+str(UDP_Length[pro])+", Checksum: "+Checksum[pro]+'\n')
                    print("UDP Length: {}, Checksum: {}".format(UDP_Length[pro],Checksum[pro]))
                    file.write("Data: "+str(Payload[pro])+'\n\n')
                    print("Data: {}".format(Payload[pro]))
                elif(select_protocol == 'UDP'):
                    file.write("Src_Port: " + str(Src_Port[pro]) + ", Des_Port: " + str(Des_Port[pro]) + "\n")
                    print("Src Port: {}, Des Port: {}".format(Src_Port[pro], Des_Port[pro]))
                    file.write("UDP_Length: " + str(UDP_Length[pro]) + ", Checksum: " + Checksum[pro] + '\n')
                    print("UDP Length: {}, Checksum: {}".format(UDP_Length[pro], Checksum[pro]))
                    file.write("Data: " + str(Payload[pro]) + '\n\n')
                    print("Data: {}".format(Payload[pro]))
                elif(select_protocol == 'ICMP'):
                    file.write('Type: '+str(Type[pro])+', Code: '+str(Code[pro])+'\n')
                    print("Type: {} Code:{}".format(Type[pro],Code[pro]))
                    file.write('Checksum: '+Checksum[pro]+'\n')
                    print("Checksum: {}".format(Checksum[pro]))
                    file.write("Data: " + str(Payload[pro]) + '\n\n')
                    print("Data: {}".format(Payload[pro]))