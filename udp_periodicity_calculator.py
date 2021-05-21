import pyshark
import argparse
import statistics

def mean_stdev(data):
    '''
    Calculate mean and strdev of the list with udp periodicity
    : input: a list with values
    : return: mean - calculated mean of a list
              st_dev - standart deviation of a list
    '''
    mean = statistics.mean(data)
    stdev = statistics.stdev(data)
    return mean, stdev


  
def udp_periodicity(path_to_capture):
    '''
    Function to calculate periodity in packets sent over UDP for the tuple source IP - destination IP.
    The function assigns the label malicious or normal based on the mean and standard deviation values.
    :input: path to capture
    :output: a dictionary, key - tuple source IP and destination IP
                           value - mean, standard deviation and label
    '''

    udp_timestamps = {}
    udp_timestamps_difference = {}
    udp_mean_stdev = {}
    cap = pyshark.FileCapture(path_to_capture, display_filter='udp')
    for packet in cap:
        if hasattr(packet, 'ipv6'):
            src_addr = packet.ipv6.src
            dst_addr = packet.ipv6.dst
        else:
            src_addr = packet.ip.src
            dst_addr = packet.ip.dst

        key = '-'.join([src_addr,dst_addr])
        timest = float(packet.frame_info.time_epoch)
        if key in udp_timestamps and len(udp_timestamps_difference[key]) < 5:
            last_time = udp_timestamps[key]
            udp_timestamps_difference[key].append(round(timest - last_time))
            udp_timestamps[key] = timest
        elif key not in udp_timestamps:
            udp_timestamps_difference[key] = []
            udp_timestamps[key]=timest
        
        if key not in udp_mean_stdev and len(udp_timestamps_difference[key])==5:
            udp_mean, udp_stdev = mean_stdev(udp_timestamps_difference[key])
            udp_mean_stdev[key] = {'mean': udp_mean, 'stdev': udp_stdev}
            if udp_stdev < 0.5 and udp_mean > 10:
                udp_mean_stdev[key]['label'] = 'malicious'
            else:
                udp_mean_stdev[key]['label'] = 'normal'
    return udp_mean_stdev

if __name__ == '__main__':
    # Parse the parameters
    parser = argparse.ArgumentParser(usage = "./iterator.py -r <path-to-capture>")
    parser.add_argument('-r','--capture', metavar='<capture>',action='store', required=True,
                        help='path to the capture.')

    args = parser.parse_args()

    if args.capture:
        path_to_capture = args.capture

    udp_mean_stdev = udp_periodicity(path_to_capture)
    print(udp_mean_stdev)

