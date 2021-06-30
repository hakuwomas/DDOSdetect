from traffic_analyzer import traffic_analyzer
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage format: python dbs_ids.py <iface>')
        exit(0)

    ids = traffic_analyzer(sys.argv[1])
    print('IDS successfully initialized.')
    ids.sniff_packets()            

    exit(0)

