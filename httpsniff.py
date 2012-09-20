
#!/usr/bin/env python2

import pcap
import sys
import string
import time
import socket
import struct
from termcolor import cprint
from cStringIO import StringIO

protocols={socket.IPPROTO_TCP:'tcp',
           socket.IPPROTO_UDP:'udp',
           socket.IPPROTO_ICMP:'icmp'}


DUMP_ONLY_FIRST_IN_EACH_DIR = True
SNIP_DATA = 500
seen_flows = dict()

def decode_ip_packet(s):
    d = {}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    if d['protocol'] in (socket.IPPROTO_TCP, socket.IPPROTO_UDP):
        d['src_port'] = socket.ntohs(struct.unpack('H',d['data'][:2])[0])
        d['dst_port'] = socket.ntohs(struct.unpack('H',d['data'][2:4])[0])

        if d['protocol'] == socket.IPPROTO_TCP:
            d['seq'] = pcap.ntoa(struct.unpack('i',d['data'][4:8])[0])
            d['ack'] = pcap.ntoa(struct.unpack('i',d['data'][8:12])[0])

            d['data_offset'] = (ord(d['data'][12]) & 0xf0) >> 4
            if len(d['data']) > d['data_offset'] * 4:
                d['payload'] = d['data'][d['data_offset']*4:]
    return d


def dumphex(s):
  bytes = map(lambda x: '%.2x' % x, map(ord, s))
  for i in xrange(0,len(bytes)/16):
    print '    %s' % string.join(bytes[i*16:(i+1)*16],' ')
  print '    %s' % string.join(bytes[(i+1)*16:],' ')
    

def try_dump_pretty(s):
    io = StringIO(s)
    for line in io:
        print line


def is_seen_flow(packet):
    k = (packet['source_address'], packet['src_port'], packet['destination_address'], packet['dst_port'])
    return k in seen_flows

def mark_seen_flow(packet):
    k = (packet['source_address'], packet['src_port'], packet['destination_address'], packet['dst_port'])
    seen_flows[k] = 1

def seen_opposite_flow(packet):
    k = (packet['destination_address'], packet['dst_port'], packet['source_address'], packet['src_port'])
    return k in seen_flows


def print_packet(pktlen, data, timestamp):
    if not data:
        return

    should_output = not DUMP_ONLY_FIRST_IN_EACH_DIR
    if data[12:14] == '\x08\x00':
        decoded = decode_ip_packet(data[14:])
        if DUMP_ONLY_FIRST_IN_EACH_DIR and not is_seen_flow(decoded):
            should_output = True

        print '\n%s.%f %s:%d > %s:%d' % (time.strftime('%H:%M',
                                                 time.localtime(timestamp)),
                                   timestamp % 60,
                                   decoded['source_address'],
                                   decoded['src_port'],
                                   decoded['destination_address'],
                                   decoded['dst_port'])
        #for key in ['version', 'header_len', 'tos', 'total_len', 'id',
        #            'flags', 'fragment_offset', 'ttl']:
        #    print '  %s: %d' % (key, decoded[key])
        #print '  protocol: %s' % protocols[decoded['protocol']]
        #print '  header checksum: %d' % decoded['checksum']
        if should_output:
            if 'payload' in decoded:
                cprint(decoded['payload'][:SNIP_DATA], 'blue' if seen_opposite_flow(decoded) else 'yellow')
                mark_seen_flow(decoded)

            #try_dump_pretty(decoded['data'])
            #dumphex(decoded['data'])
 

if __name__=='__main__':

  if len(sys.argv) < 3:
    print 'usage: sniff.py <interface> <expr>'
    sys.exit(0)
  p = pcap.pcapObject()
  #dev = pcap.lookupdev()
  dev = sys.argv[1]
  net, mask = pcap.lookupnet(dev)
  # note:  to_ms does nothing on linux
  p.open_live(dev, 1600, 0, 100)
  #p.dump_open('dumpfile')
  p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

  # try-except block to catch keyboard interrupt.  Failure to shut
  # down cleanly can result in the interface not being taken out of promisc.
  # mode
  #p.setnonblock(1)
  try:
    while 1:
      p.dispatch(1, print_packet)

    # specify 'None' to dump to dumpfile, assuming you have called
    # the dump_open method
    #  p.dispatch(0, None)

    # the loop method is another way of doing things
    #  p.loop(1, print_packet)

    # as is the next() method
    # p.next() returns a (pktlen, data, timestamp) tuple 
    #  apply(print_packet,p.next())
  except KeyboardInterrupt:
    print '%s' % sys.exc_type
    print 'shutting down'
    print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
