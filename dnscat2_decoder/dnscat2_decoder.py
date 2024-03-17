from scapy.all import *
import binascii
import argparse

def get_args():
    # example: python3 dnscat2_decoder.py -f suspicious_traffic.pcap  -s '192.168.157.144' -t '192.168.157.145' -d 'microsofto365.com' -o outfile
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--file', help='Path to pcap file', nargs='?', required=True)
    parser.add_argument('-s','--source_host', help='IPv4 address of source host', nargs='?', required=True)
    parser.add_argument('-t','--target_host', help='IPv4 address of destination host', nargs='?', required=True)
    parser.add_argument('-d','--domain', help='Malicious Domain', nargs='?', required=True)
    parser.add_argument('-o','--output_file', help='File to write decoded traffic to', nargs='?', required=True)
    return parser.parse_args()

def extract_c2c(src_h, dst_h, m_domain, pcap_file):
    capture = PcapNgReader(pcap_file)
    msg_type_msg = 1
    
    c2c = []
    for pkt in capture:
        # Pkt is qury between infected host and mal server
        if pkt.haslayer('IP') and src_h == pkt['IP'].src  and dst_h == pkt['IP'].dst and pkt.haslayer('DNS'):
            # Domain is malicious domain
            if m_domain in pkt['DNSQR'].qname.decode():
               # remove ctlr bytes, newlines and .
               # see: https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md#messages
               # and https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md#encoding               
               c2_pkt = pkt['DNSQR'].qname.decode().split(m_domain)[0].replace('.', '').replace('\n', '')
               # check if msg
               if bytearray.fromhex(c2_pkt)[2] == msg_type_msg:
                   c2c.append(c2_pkt[18:])

    return c2c


def extract_c2c2():
    p = rdpcap('/workspaces/python-2/suspicious_traffic.pcap')
    src_h = '192.168.157.144'
    dst_h = '192.168.157.145'
    m_domain = 'microsofto365.com'


    msg_type_msg = 1 

    pkt = p[48479]
    raw_c2c = []
    
    return raw_c2c




def decode_c2c(c2c):
    d_c2c = ""
    for c in c2c:
        d_c2c += binascii.unhexlify(c).decode('utf-8', errors='ignore')
   
    return d_c2c

def main():
    #args = get_args()
    
    #c2c = extract_c2c(args.source_host, args.target_host, args.domain, args.file)
 
    p = '/workspaces/python-2/suspicious_traffic.pcap'
    src_h = '192.168.157.144'
    dst_h = '192.168.157.145'
    m_domain = 'microsofto365.com'
    
    
    c2c = extract_c2c(src_h, dst_h, m_domain, p)
    with open('out', 'w') as ofh:
        ofh.write(decode_c2c(c2c))
    
    
if __name__ == '__main__':
    main()
