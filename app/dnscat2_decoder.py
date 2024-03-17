from scapy.all import *

def extract_c2c(src_h, dst_h, m_domain, pcap_file):
    capture = PcapNgReader(pcap_file)
    
    c2c = ()
    for pkt in capture:
        # Pkt is DNS between the two hosts
        if pkt.haslayer('IP') and (src_h == pkt['IP'].src or src_h == pkt['IP'].dst) and (dst_h == pkt['IP'].src or dst_h == pkt['IP'].dst):
            # Domain is malicious domain
            if m_domain in pkt['DNSQR'].qname.decode():
               c2c.append(pkt['DNSQR'].qname.decode().split(m_domain)[0].replace('.', ''))
               
            elif m_domain in pkt['DNSRR'].decode():
                c2c.append(pkt['DNSRR'].qname.decode().split(m_domain)[0].replace('.', ''))

    return c2c

def main():
    pcap_file = '/workspaces/python-2/suspicious_traffic.pcap'
    src_h = '192.168.157.144'
    dst_h = '192.168.157.145'
    m_domain = 'microsofto365.com'
    
    c2c = extract_c2c(src_h, dst_h, m_domain, pcap_file)


    
    

if __name__ == '__main__':
    main()