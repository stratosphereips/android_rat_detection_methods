from zat import zeek_log_reader
import argparse
import csv

def read_csv_file(path_to_csv_file):
    '''
    Function to read csv file with the common ports. 
    ''' 
    common_ports = set()
    with open(path_to_csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            common_ports.add(int(row[1]))
    return common_ports

def unique_ports_calculator(path_to_zeek_log, host=False):
    '''
    Function to get unique dst IPs and dst ports and filter if dst ports are not common.
    :input: path to Zeek conn.log
    :output: a dictionary: key - a tuple - src IP - dst IP
                           value - a list of destination ports
    '''
    reader = zeek_log_reader.ZeekLogReader(path_to_zeek_log)
    unique_dst_ip_port = {}
    common_ports = read_csv_file('services.csv')
    for row in reader.readrows():
        src_addr = row['id.orig_h']
        dst_addr = row['id.resp_h']
        dst_port = row['id.resp_p']
        key = '-'.join([src_addr,dst_addr])
        if dst_port == 0 or dst_addr == host:
            continue
        if key in unique_dst_ip_port:
            unique_dst_ip_port[key].add(dst_port)
        else:
            unique_dst_ip_port[key] = set([dst_port])
    malicious_ips_ports = {}

    for srcip_dstip,ports in unique_dst_ip_port.items():
        if len(ports)>1 and not any(port in common_ports for port in ports):
            malicious_ips_ports[srcip_dstip]=ports

    return malicious_ips_ports
if __name__ == '__main__':
    # Parse the parameters
    parser = argparse.ArgumentParser(usage = "./iterator.py -r <path-to-capture>")
    parser.add_argument('-r','--capture', metavar='<capture>',action='store', required=True,
                        help='path to Zeek log')
    parser.add_argument('-j', '--host', metavar='<host>', action='store', required=False,
                        help='host IP address')

    args = parser.parse_args()

    if args.capture:
        path_to_capture = args.capture
    if args.host:
        host_ip = args.host
    else:
        host_ip = False

    malicious_ips_ports  = unique_ports_calculator(path_to_capture, host_ip)
    print(malicious_ips_ports)
