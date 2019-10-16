# dtn-bpbis-tcpcl

Source for for TCPCLv4.
The final specification is hosted at <https://datatracker.ietf.org/doc/draft-ietf-dtn-tcpclv4/>

# Demo Convergence Layer Agent

The demo TCPCL agent implements the corresponding specification draft.
A TCPCL agent is symmetric, there is no notion of a single agent being a "server" or a "client".
The demo agent hosted here has an optional startup action, which is to either listen on an address+port (act as a passive node in a TCPCL session) or to connect to an address+port (act as an active node in a TCPCL session).
Once the agent is started, regardless of which or if a startup action was given, the agent can be commanded via D-Bus to listen/connect for later sessions or to transport bundles over existing sessions.

## Starting the Agent

All of these commands require either a local installation of the python packages, or using an environment such as
```
PYTHONPATH=demo-agent/src
```

An insecure session on the `localhost` address can be established with commands:
```
python3 -m tcpcl.agent --bus-service=tcpcl.Server --nodeid=dtn:server --tls-disable listen --address=localhost
python3 -m tcpcl.agent --bus-service=tcpcl.Client --nodeid=dtn:client --tls-disable --stop-on-close connect localhost
```

To use Fedora/CentOS7 system-default localhost PKI use:
```
python3 -m tcpcl.agent --bus-service=tcpcl.Server --nodeid=dtn:server --tls-key=/etc/pki/tls/private/localhost.key --tls-cert=/etc/pki/tls/certs/localhost.crt listen --address=localhost
python3 -m tcpcl.agent --bus-service=tcpcl.Client --nodeid=dtn:client --tls-key=/etc/pki/tls/private/localhost.key --tls-cert=/etc/pki/tls/certs/localhost.crt --stop-on-close connect localhost
```

## Commanding the Agent
The agent can be accessed via D-Bus based on the `bus-service` name given on the command line.

### Agent Interface

The agent itself is accessible via the object `/org/ietf/dtn/tcpcl/Agent` with interface `org.ietf.dtn.tcpcl.Agent`.

The methods in this interface are:

- `listen(address, port)` to cause the agent to listen on a given port.
- `listen_stop(address, port)` to cause the agent to stop listening.
- `connect(address, port)` to cause the agent to attempt a connection to a peer.
- `shutdown()` causes any open sessions to be terminated, which itself may wait on in-progress transfers to complete. The return value is `True` if the agent stopped immediately, or `False` if sessions are being waited on before stopping.
- `stop()` forces the process to exit immediately and not wait.

The signals in this interface are:

- `connection_opened(path)` is emitted when a new TCP connection is opened and session negotiation begins. This does not mean the session is established and ready for use, just that a session may be established on the new connection.
- `connection_closed(path)` is emitted when a TCP connection is closed.

### Session Interface

Each established session is accessible via the object `/org/ietf/dtn/tcpcl/Contact{N}`, where `{N}` is some unique identifier number, with interface `org.ietf.dtn.tcpcl.Contact`.

Notable methods in this interface are:

- `is_sess_idle()` which returns true when the session is established, ready for use, and no messages are being sent or recevied.
- `is_secure()` which returns true if TLS is used to secure the session.
- `send_bundle_get_queue()` which returns Transfer IDs which are queued for sending.
- `send_bundle_file(filepath)` which queues transfer of a file directly from the filesystem. The agent must have sufficient permission to read from the file. The return value is the new Transfer ID.
- `send_bundle_data(bytes)` which queues transfer of data from the message itself. The return value is the new Transfer ID.
- `recv_bundle_get_queue()` which returns the Transfer IDs which have been received and are ready.
- `recv_bundle_pop_file(bid, filepath)` which takes a received transfer directly into the filesystem. The `bid` argument is the Transfer ID to pop. The agent must have sufficient permission to write to the file.
- `recv_bundle_pop_data(bid)` which takes a received transfer and returns its contents as a byte array. The `bid` argument is the Transfer ID to pop. The return value is the transfer data itself.
- `terminate(reason_code)` which performs the session termination procedure, which waits for any in-progress transfers to complete then closes the TCP connection.
- `close()` which closes the TCP connection immediately.

Files can be sent with commands similar to:
```
dbus-send --print-reply --dest=tcpcl.Client /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.send_bundle_file string:"/etc/hostname"
```

Files can be popped out of the agent after reception with commands similar to:
```
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_get_queue
```
to get the received Transfer ID, and
```
dbus-send --print-reply --dest=tcpcl.Server /org/ietf/dtn/tcpcl/Contact0 org.ietf.dtn.tcpcl.Contact.recv_bundle_pop_file string:1 string:/tmp/dest
```
to actually save the received bundle.

## Network Sequencing Tests

There is a full end-to-end agent test which can be run by the command:
```
python3 -m tcpcl.test.bundlegen <gentype> <gencount>
```
where `gentype` of "fullvalid" generates valid BPv7 test bundles, and `gencount` is the total number of bundles to generate and transfer.

# Wireshark Protocols and Dissectors

The wireshark modules require development environment for wireshark itself, cmake, and some build tool.
The reference commands below use the Ninja build tool, but that is not required.

Building the wireshark modules can be done with a command sequence similar to:
```
MODULE_VERS=$(pkg-config --variable=VERSION_RELEASE wireshark)
mkdir -p wireshark-plugin/build
cd wireshark-plugin/build/
cmake .. -DCMAKE_BUILD_TYPE=Debug -DINSTALL_MODULE_PATH=${HOME}/.local/lib/wireshark/plugins/${MODULE_VERS}/epan/ -G Ninja
ninja install
```

At this point the two modules "libtcpclv4" and "libbpv7" will be installed in the wireshark plugin path and will be loaded at next wireshark application startup.

The protocol names registered are "tcpclv4" and "bpv7", each of which has some set of parameters and field names.
