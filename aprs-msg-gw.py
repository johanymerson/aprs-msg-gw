#!/usr/bin/env python3.4

# Copyright 2017 Johan Ymerson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import imaplib, smtplib, email, sys, socket, random, hashlib, time, traceback
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Callsign of this GW:
mycall = 'MYCALL-10'

senders = {
    'name@adomain.com': 'MYCALL',
    'othername@somedomain.com': 'A2CALL',
}

# Signals to track all the time:
track = [ 'MYCALL*', 'A2CALL*' ]

# APRS-IS server pool and your APRS-IS password:
aprsis_server = 'euro.aprs2.net'
aprsis_pass = ''

# Your IMAP server, username and password
mail_server = 'imap.mydomain.com'
mail_user = 'aprs'
mail_pass = ''

def verify_callsign(call):
    parts = call.split('-')

    # Max 2 parts separated by -
    # Default to SSID 0 if - is missing
    if len(parts) > 2:
        return False
    if len(parts) == 2:
        try:
            ssid = int(parts[1])
        except:
            return False
    else:
        ssid = 0

    # SSID 0-15
    if ssid > 15:
        return False

    # Base callsign length 3-6 chars
    if len(parts[0]) < 3 or len(parts[0]) > 6:
        return False

    # Only alphanumeric uppercase chars in base callsign
    for c in parts[0]:
        if c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
            return False

    return True

def aprsis_send_msg(dstsig, text, msgid):
    # Pad signal to 9 chars
    while len(dstsig) < 9:
        dstsig = dstsig + ' '

    # APRS-IS always use the path TCPIP*
    pkt = "%s>%s,TCPIP*," % (mycall, tocall)
    pkt = pkt + "%s::%s:%s{%i\r\n" % (mycall, dstsig, text, msgid)
    is_s.send(pkt.encode('ascii', 'replace'))
    print(pkt.encode('ascii', 'replace'))

def process_aprsis():
    try:
        p = is_s.recv(256)
    except socket.timeout:
        return

    p = p.decode('ascii', 'replace')
    
    try:
        if p[0] == '#':
            return
        
        src, rest = p.split('>', 1)
        path, data = rest.split(':', 1)

        # Only track messages capable devices
        if data[0] in "=@`":
            heard[src] = {'lastheard': datetime.now()}

        print(p)
        
        if not data[0] == ':':
            # Not a message packet
            return

        dst, msg = data[1:].split(':', 1)
        dst = dst.strip()
        msg = msg.strip()

        if not msg[0:3] == "ack":
            return
        
        ackid = int(msg[3:])
        if ackid in messages:
            print("Ack on message %s" % ackid)
            messages[ackid]['delivered'] = True
            messages[ackid]['ackedby'] = src
    except:
        pass

def aprsis_update_filter():
    cmd = "#filter b/%s" % mycall
    for call in track:
        cmd = "%s b/%s" % (cmd, call)
    cmd.strip()
    cmd = cmd + "\r\n"
    is_s.send(cmd.encode('ascii'))
    print(cmd)

def send_reply(src, dst, subject, body):
    msg = MIMEMultipart()
    msg['from'] = src
    msg['to'] = dst
    msg['subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    s = smtplib.SMTP(mail_server, 587)
    s.starttls()
    s.login(mail_user, mail_pass)
    s.send_message(msg)
    s.quit()

def process_mails(imap, f, heard_only = False):
    dummy,ret  = imap.uid('search', None, f)
    for nr in ret[0].split():
        dummy, msg = imap.uid('fetch', nr, '(RFC822)')
        msg = msg[0][1]
        
        # Generate a message ID
        h = hashlib.new('sha1')
        h.update(msg)
        msgid = h.hexdigest()[:5]
        msgid = int(msgid, 16)
        msgid = msgid % 100000

        msg =  email.message_from_bytes(msg)
        if 'reply-to' in msg:
            replyto = msg['reply-to']
        else:
            replyto = msg['from']

        if msgid in messages and messages[msgid]['retries'] > 10:
            print("Too many retries")
            send_reply(msg['to'], replyto,
                       "Re: " + msg['subject'],
                       "Message NOT delivered, too many retries.\r\n")
            imap.uid('store', nr, '+FLAGS', '\\Deleted')
            del messages[msgid]
            continue

        if msgid in messages and messages[msgid]['delivered']:
            print("Message delivered")
            send_reply(msg['to'], replyto,
                       "Re: " + msg['subject'],
                       "Message delivered to %s.\r\nView on map:\r\nhttp://aprs.fi/#!call=a%%2F%s" % (messages[msgid]['ackedby'], messages[msgid]['ackedby']))
            imap.uid('store', nr, '+FLAGS', '\\Deleted')
            del messages[msgid]
            continue
            
        # Extract source address from sender
        src = replyto
        if '<' in src:
            src = src[src.find('<')+1:src.find('>')]

        # Map to callsign, or use mycall
        if src in senders:
            src = senders[src]
        else:
            src = mycall

        dst = msg['to']
        if '<' in dst:
            dst = dst[dst.find('<')+1:dst.find('>')]
        dst = dst[:dst.find('@')]
        dst = dst.upper()
        if not verify_callsign(dst):
            print("Malformed callsign %s" % dst)
            send_reply(msg['to'], replyto,
                       "Re: " + msg['subject'],
                       "Malformed callsign %s." % dst)
            imap.uid('store', nr, '+FLAGS', '\\Deleted')
            continue

        # Use subject as messages text (ignore the body)
        text = msg['subject']

        # If destination is missing -SSID, find out what station we heard last matching the
        # base callsign and send to that.
        parts = dst.split('-')
        if len(parts) == 1:
            last_heard_call = None
            for s in heard:
                if dst == s[:len(dst)] and s[len(dst)] == '-':
                    if last_heard_call and heard[last_heard_call]['lastheard'] > heard[s]['lastheard']:
                        # We already have a call heard later than this
                        continue
                    last_heard_call = s
            if last_heard_call:
                print("Sending message for %s to %s instead" % (dst, last_heard_call))
                dst = last_heard_call
        
        # If heard_only is set, only send to stations heard the last 5 minutes
        if heard_only:
            if not dst in heard:
                return
            if datetime.now() - heard[dst]['lastheard'] > timedelta(300):
                return
        
        print("From %s to %s: %s" % (src, dst, text))

        # Mark message seen and start listening for the call
        imap.uid('store', nr, '+FLAGS', '\\Seen')
        if not src in track:
            track.append(src)
        if not dst in track:
            track.append(dst)
        aprsis_update_filter()

        # Send the message
        aprsis_send_msg(dst, text, msgid)
        if msgid in messages:
            messages[msgid]['retries'] = messages[msgid]['retries'] + 1
        else:
            messages[msgid] = {'dst': dst, 'src': src, 'retries': 0, 'delivered': False}

def aprs_msg_gw():
    global is_s, imap

    # Connect to APRS-IS (close previous socket if needed)
    if is_s:
        is_s.close()
    is_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_s.connect((aprsis_server, 14580))
    is_s.settimeout(1)

    # Login to APRS-IS
    myfilter = "b/%s" % mycall
    cmd = "user %s pass %s filter %s\n" % (mycall, aprsis_pass, myfilter)
    is_s.send(cmd.encode('ascii'))
    # Start tracking calls in track list
    aprsis_update_filter()

    # Login to IMAP server (close previous socket if needed)
    if imap:
        imap.logout()
    imap = imaplib.IMAP4_SSL(host=mail_server)
    imap.login(mail_user, mail_pass)
    imap.select()

    # Process all mails once
    process_mails(imap, 'NOT DELETED')

    # Main loop
    while True:
        # Process mails every 60 seconds
        lastcheck = datetime.now()
        timeout = timedelta(seconds=60)

        print("Currently tracking:")
        for call in track:
            print("    %s" % call)
        print("Waiting for ack on:")
        for m in messages:
            print("    %i (%s)" % (m, str(messages[m])))
        print("Stations heard:")
        for s in heard:
            print("    %s (%s)" % (s, heard[s]['lastheard']))

        # Send unseen messages immediately
        process_mails(imap, '(UNSEEN)')

        while datetime.now() - lastcheck < timeout:
            process_aprsis()

        # Send queued messages to heard stations
        process_mails(imap, 'NOT DELETED', heard_only=True)

    # Clean up
    imap.close()
    imap.logout()
    is_s.close()

tocall = 'APRS'
is_s = None
imap = None
messages = {}
heard = {}

# Restart the gateway if something goes wrong (ie lost connection to APRS-IS or IMAP server)
while True:
    try:
        aprs_msg_gw()
    except:
        traceback.print_exc()
        print("Restarting APRS Message Gateway...")
        # Wait 10 seconds a try again
        time.sleep(10)
