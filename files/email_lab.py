#!/usr/bin/env python3

import time
from mininet.net import Mininet
from mininet.node import OVSSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class EmailDNSHost(Host):
    """Host that can run background services (no changes needed)."""
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)

def setup_mail_server(host, domain):
    """Start a simple, permissive SMTP server on port 25 inside `host`."""
    info(f'*** Setting up mail server on {host.name} for {domain}\n')

    # Write the SMTP server safely via heredoc (no quote escaping headaches)
    host.cmd(f"""cat > /tmp/smtp_server.py <<'EOF'
#!/usr/bin/env python3
import socket, threading

DOMAIN = "{domain}"

def handle_smtp_connection(conn, addr):
    try:
        conn.send(b"220 " + DOMAIN.encode("ascii", "ignore") + b" ESMTP Ready\\r\\n")
        data_mode = False
        while True:
            line = conn.recv(1024)
            if not line:
                break
            msg = line.decode('ascii', errors='ignore').strip()
            print(f"SMTP[{{addr[0]}}]: {{msg}}")

            upper = msg.upper()

            if data_mode:
                # DATA mode ends when a single dot on its own line is received
                if msg == '.':
                    conn.send(b"250 Message accepted\\r\\n")
                    data_mode = False
                else:
                    # keep consuming; no response until '.'
                    pass
                continue

            if upper.startswith('HELO') or upper.startswith('EHLO'):
                conn.send(b"250 Hello\\r\\n")
            elif upper.startswith('MAIL FROM'):
                conn.send(b"250 OK\\r\\n")
            elif upper.startswith('RCPT TO'):
                conn.send(b"250 OK\\r\\n")
            elif upper == 'DATA':
                conn.send(b"354 Start mail input; end with <CRLF>.<CRLF>\\r\\n")
                data_mode = True
            elif upper == 'QUIT':
                conn.send(b"221 Goodbye\\r\\n")
                break
            else:
                conn.send(b"250 OK\\r\\n")
    except Exception as e:
        print(f"SMTP Error: {{e}}")
    finally:
        conn.close()

def start_smtp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 25))
    srv.listen(5)
    print(f"SMTP Server listening on port 25 for {{DOMAIN}}")
    while True:
        c, a = srv.accept()
        t = threading.Thread(target=handle_smtp_connection, args=(c, a), daemon=True)
        t.start()

if __name__ == "__main__":
    start_smtp_server()
EOF
""")
    host.cmd('chmod +x /tmp/smtp_server.py')
    # host.cmd('python3 /tmp/smtp_server.py >/tmp/smtp.stdout 2>&1 & echo $!')
    host.cmd('bash -lc "set +m; nohup python3 /tmp/smtp_server.py >/tmp/smtp.stdout 2>&1 & disown"')

    time.sleep(0.7)

def write_sample_emails(client):
    """Write the example emails using heredocs to avoid quoting issues."""
    info('*** Creating sample emails for analysis\n')

    client.cmd(r"""bash -lc "cat > /tmp/legit_email.txt <<'EOF'
From: commandant@westpoint.edu
To: cadet.smith@westpoint.edu
Subject: Training Schedule Update
Return-Path: <commandant@westpoint.edu>
Received: from mail.westpoint.edu (mail.westpoint.edu [10.0.0.25])

Cadets,

The morning PT schedule has been updated...

V/R,
Commandant
EOF" """)

    client.cmd(r"""bash -lc "cat > /tmp/spoofed_email.txt <<'EOF'
From: commandant@westpoint.edu
To: cadet.jones@westpoint.edu
Subject: URGENT: CAC Verification Required
Return-Path: <noreply@westpoint-secure.com>
Received: from mail.westpoint-secure.com (westpoint-secure.com [10.0.0.26])

URGENT SECURITY NOTICE:

Your CAC card requires immediate verification. Click here: http://westpoint-secure.com/verify

Failure to verify within 24 hours will result in account suspension.

Commandant's Office
EOF" """)

def mailOnlyNet():
    """Create network with mail servers and a client (no DNS)."""
    net = Mininet(controller=None, switch=OVSSwitch, host=EmailDNSHost)

    info('*** Adding hosts\n')
    client     = net.addHost('client',   ip='10.0.0.10/24')
    mail_legit = net.addHost('mail1',    ip='10.0.0.25/24')
    mail_evil  = net.addHost('mail2',    ip='10.0.0.26/24')

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', failMode='standalone')

    info('*** Creating links\n')
    for h in [client, mail_legit, mail_evil]:
        net.addLink(h, s1)

    info('*** Starting network\n')
    net.start()

    info('*** Network ping test\n')
    net.pingAll()

    # SMTP servers
    setup_mail_server(mail_legit, 'westpoint.edu')
    setup_mail_server(mail_evil,  'westpoint-secure.com')

    # Sample emails
    write_sample_emails(client)

    info('*** Waiting for services to initialize...\n')
    time.sleep(1.5)

 

    info('*** SMTP:\n')
    info('***   client telnet 10.0.0.25 25\n')
    info('***   client telnet 10.0.0.26 25\n')
    info('*** EMAIL HEADERS:\n')
    info('***   client cat /tmp/legit_email.txt\n')
    info('***   client cat /tmp/spoofed_email.txt\n')

    CLI(net)
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    mailOnlyNet()
