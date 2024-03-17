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
    
    c2c = []
    for pkt in capture:
        # Pkt is qury between infected host and mal server
        if pkt.haslayer('IP') and src_h == pkt['IP'].src  and dst_h == pkt['IP'].dst and pkt.haslayer('DNS'):
            # Domain is malicious domain
            if m_domain in pkt['DNSQR'].qname.decode():
               # remove ctlr bytes, newlines and .
               # see: https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md#messages
               # and https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md#encoding
               c2c.append(pkt['DNSQR'].qname.decode().split(m_domain)[0][18:].replace('.', '').replace('\n', ''))

    return c2c

def decode_c2c(c2c):
    d_c2c = ""
    for c in c2c:
        d_c2c += binascii.unhexlify(c).decode('utf-8', errors='ignore')
   
    return d_c2c

def main():
    args = get_args()
    
    c2c = extract_c2c(args.source_host, args.target_host, args.domain, args.file)
    with open(args.output_file, 'w') as ofh:
        ofh.write(decode_c2c(c2c))
    
    
if __name__ == '__main__':
    main()
