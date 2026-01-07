import socket
import select
import struct

def get_local_ip():
    """ Află IP-ul local folosit pentru a ieși în internet. """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Nu trimite nimic efectiv, doar calculează ruta
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def create_udp_socket():
    """ Creează socket UDP pentru trimiterea pachetelor."""
    # creare socket SOCK_DGRAM pentru UDP
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # returnare socket
    return udp_sock


def create_icmp_raw_socket():
    """ Creează socket RAW pentru recepția pachetelor ICMP."""
    # creare socket RAW cu filtrare IPPROTO_ICMP
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # legare socket la adresa locală ("", 0)
    # FIX: Facem bind pe IP-ul local explicit pentru a ajuta Windows-ul
    local_ip = get_local_ip()
    icmp_sock.bind((local_ip, 0))

    # returnare socket
    return icmp_sock

def set_ttl(udp_sock, ttl_value):
    """ Configurează câmpul TTL la nivel IP pentru socket-ul UDP."""
    # aplicare setsockopt cu IP_TTL
    udp_sock.setsockopt(socket.IPPROTO_IP,socket.IP_TTL, ttl_value)


def send_udp_probe(udp_sock, dest_addr, dest_port, payload=b"test"):
    """ Trimite un pachet UDP către adresa/portul țintă."""
    # trimitere pachet UDP către dest_addr:dest_port
    udp_sock.sendto(payload, (dest_addr, dest_port))
    return


def receive_icmp_reply(icmp_sock, timeout=1.0):
    """
    Așteaptă un pachet ICMP cu timeout.
    Întoarce (data, addr) sau (None, None).
    """
    # folosire select.select pentru așteptarea cu timeout
    ready,_,_ = select.select([icmp_sock], [], [], timeout)
    # dacă există date, returnare conținut pachet și adresa sursă
    if ready:
        data, addr = icmp_sock.recvfrom(1024)
        print("Received from: ",addr)
        print("Data received: ",data)
        return data,addr
    # altfel, returnare (None, None)
    return None, None


def parse_icmp_packet(packet):
    """ Parsează pachetul ICMP pentru tip, cod și datele pachetului original.
    Întoarce câmpurile utile (icmp_type, icmp_code, ...).
    """
    # calcul lungimea reală a headerului IP (IHL)
    ihl = (packet[0] & 0xf) *4
    # extragere header ICMP (8 bytes)
    icmp_header = packet[ihl:ihl+8]
    # interpretare câmpuri Type și Code
    # Type (1B), Code (1B), Checksum (2B), Rest/Unused (4B)
    icmp_type, icmp_code, checksum, rest = struct.unpack("!BBHI",icmp_header)
    # extragere pachet IP original încapsulat în mesajul ICMP
    # dacă pachetul original este UDP, extragere porturi
    original_protocol = None
    src_port = None
    dst_port = None
    # verificare daca pachetul e mesaj de eroare: type 3 - Dest Unreachable sau type 11 - Time Exceeded
    if icmp_type in [3,11]:
        # in interiorul pachetului se gasesc header-ul pachetului IP original + primii 8 biti din pachetul UDP = source port,dest port
        inner_ip_offset = ihl + 8
        try:
            # tipul protocolului din pachetul IP interior se gaseste la offsetul 9
            original_protocol = packet[inner_ip_offset+9]

            # udp = 17
            if original_protocol == 17:
                #trebuie sa traversam headerul IP pentru a ajunge la cel UDP
                inner_ip_ihl = (packet[inner_ip_offset] & 0x0f)*4
                udp_offset = inner_ip_offset + inner_ip_ihl
                udp_header_data = packet[udp_offset:udp_offset+4]
                src_port, dst_port = struct.unpack("!HH", udp_header_data)
        except IndexError:
            #pachet trunchiat sau malformat
            pass

        # returnare valori (type, code și orice considerați a fi de folos)
        return icmp_type,icmp_code,original_protocol,src_port,dst_port,




def main():

    udp_sock = create_udp_socket()
    icmp_sock = create_icmp_raw_socket()

    dest_ip = "8.8.8.8"
    base_port = 33434

    try:
        # bucla principală (TTL de la 1 la 20)
        for ttl in range (1,21):
            pass
            set_ttl(udp_sock, ttl)
            send_udp_probe(udp_sock, dest_ip, base_port + ttl)
            data, addr = receive_icmp_reply(icmp_sock, timeout=2.0)
            #* dacă timeout: afișare informație corespunzătoare
            if data:
                #dacă există răspuns: parsare ICMP, afișare info
                icmp_type, icmp_code, src_ip_original, src_port_original, dst_port_original = parse_icmp_packet(data)
                router_ip = addr[0]
                print(f"{ttl}\t{router_ip}\t[Type: {icmp_type} Code: {icmp_code}]")

                # oprire dacă răspunsul provine de la destinația finală
                if icmp_type == 3:
                    print("Destinatie atinsa")
                    break
            else:
                print(f"{ttl}\t*")
    except KeyboardInterrupt:
        print("Oprit.")

    udp_sock.close()
    icmp_sock.close()


if __name__ == "__main__":
    main()
