import pyshark
import argparse
import statistics

def mean_stdev(data):
    '''
    Calculate mean and strdev of the list with icmp periodicity
    : input: a list with values
    : return: mean - calculated mean of vlaues in a list
              st_dev - standart deviation of values in a list
    '''
    mean = statistics.mean(data)
    stdev = statistics.stdev(data)
    return mean, stdev



def find_icmp_request_periodicity(path_to_capture):
    '''
    Function to calculate ICMP Echo Request Messages periodity based on ICMP packets in the tuple source IP - destination IP.
    The function assigns the label malicious or normal based on the mean and standard deviation values.
    :input: path to capture
    :output: a dictionary, key - tuple source IP and destination IP
                           value - mean, standard deviation and label
    '''

    icmp_timestamps = {}
    icmp_timestamps_difference = {}
    icmp_mean_stdev = {}
    cap = pyshark.FileCapture(path_to_capture, display_filter='icmp.type==8')
    for packet in cap:
        if hasattr(packet, 'ipv6'):
            src_addr = packet.ipv6.src
            dst_addr = packet.ipv6.dst
        else:
            src_addr = packet.ip.src
            dst_addr = packet.ip.dst

        key = '-'.join([src_addr,dst_addr]) 
        timest = float(packet.frame_info.time_epoch)
        if key in icmp_timestamps and len(icmp_timestamps_difference[key]) < 5:
            last_time = icmp_timestamps[key]
            icmp_timestamps_difference[key].append(round(timest - last_time))
            icmp_timestamps[key]=timest
        elif key not in icmp_timestamps:
            icmp_timestamps_difference[key] = []
            icmp_timestamps[key]=timest
        
        if key not in icmp_mean_stdev and len(icmp_timestamps_difference[key])==5:
            icmp_mean, icmp_stdev = mean_stdev(icmp_timestamps_difference[key])
            icmp_mean_stdev[key] = {'mean':icmp_mean, 'stdev': icmp_stdev}
            if icmp_stdev<1 and icmp_mean>15:
                icmp_mean_stdev[key]['label'] = 'malicious'
            else: 
                icmp_mean_stdev[key]['label'] = 'normal'

    return icmp_mean_stdev

if __name__ == '__main__':
    # Parse the parameters
    parser = argparse.ArgumentParser(usage = "./iterator.py -r <path-to-capture>")
    parser.add_argument('-r','--capture', metavar='<capture>',action='store', required=True,
                        help='path to the capture.')

    args = parser.parse_args()

    if args.capture:
        path_to_capture = args.capture

    icmp_mean_stdev = find_icmp_request_periodicity(path_to_capture)
    print(icmp_mean_stdev)
