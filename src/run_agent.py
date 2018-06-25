''' Entry point for the agent implementation.

Two endpoints need to be established, in order:
python ./src/run_agent.py --bus-service=tcpcl.Server --eid=server --tls-disable listen
python ./src/run_agent.py --bus-service=tcpcl.Client --eid=client --tls-disable connect localhost

To use Fedora/CentOS7 system-default localhost PKI use:
python ./src/run_agent.py --bus-service=tcpcl.Server --eid=server --tls-key=/etc/pki/tls/private/localhost.key --tls-cert=/etc/pki/tls/certs/localhost.crt listen
python ./src/run_agent.py --bus-service=tcpcl.Client --eid=client --tls-key=/etc/pki/tls/private/localhost.key --tls-cert=/etc/pki/tls/certs/localhost.crt connect localhost


The agent can be accessed via dbus.

Files can be sent with message similar to:
dbus-send --print-reply --dest=tcpcl.Client /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.send_bundle_file string:"/etc/hostname"


# To pop from receiver:
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_get_queue
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_pop_file string:1 string:/tmp/dest
'''

import sys
import tcpcl.agent as agent

if __name__ == '__main__':
    sys.exit(agent.main())
