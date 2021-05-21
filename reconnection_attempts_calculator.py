from zat import zeek_log_reader
import argparse

def reconnections_calculator(path_to_zeek_log):
    '''
    Function to get calculate reconnection attempts to dst IP from the Zeek conn.log. 
    :input: path_to_zeek_log - path to Zeek conn.log
    :output: a dictionary: key - tuple src IP - dst IP
                           value - number of reconnections
    '''
    reader = zeek_log_reader.ZeekLogReader(path_to_zeek_log)
    reconnections = {}
    for row in reader.readrows():
        src_addr = row['id.orig_h']
        src_port = row['id.orig_p']
        dst_addr = row['id.resp_h']
        dst_port = row['id.resp_p']
        conn_state = row['conn_state']
        key = src_addr + '-' + dst_addr + ':' + str(dst_port)
        if dst_port == 0:
            continue
        if conn_state == 'REJ':
            reconnections[key] = reconnections.get(key,0) + 1
    malicious_reconnections = {}
    for key,count_reconnections in reconnections.items():
        if count_reconnections > 1:
            malicious_reconnections[key] = count_reconnections
    return malicious_reconnections

if __name__ == '__main__':
    # Parse the parameters
    parser = argparse.ArgumentParser(usage = "./iterator.py -r <path-to-capture>")
    parser.add_argument('-r','--capture', metavar='<capture>',action='store', required=True,
                        help='path to Zeek log.')

    args = parser.parse_args()

    if args.capture:
        path_to_capture = args.capture

    malicious_reconnections = reconnections_calculator(path_to_capture)
    print(malicious_reconnections)
