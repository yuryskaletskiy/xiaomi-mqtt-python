from past.builtins import basestring
import socket
import struct
import json
import datetime
import logging


def ensure_dict(raw):
    if isinstance(raw, dict):
        return raw

    return json.loads(raw)


class XiaomiConnector:
    """
    Connector for the Xiaomi Mi Hub and devices on multicast.
    API description: https://www.gitbook.com/book/aqara/lumi-gateway-lan-communication-api
    """

    MULTICAST_PORT = 4321
    SERVER_PORT = 9898

    MULTICAST_ADDRESS = '224.0.0.50'
    SOCKET_BUFSIZE = 1024

    def __init__(self, data_callback=None, metadata_callback=None,
                 multicast_address=MULTICAST_ADDRESS, multicast_port=MULTICAST_PORT,
                 server_port=SERVER_PORT):
        """Initialize the connector."""
        self.server_port = server_port
        self.multicast_port = multicast_port
        self.multicast_address = multicast_address
        self.metadata_callback = metadata_callback
        self.data_callback = data_callback
        self.last_tokens = dict()
        self.socket = self._prepare_socket()

        self.send_whois()

        self._devices = dict()

    def _prepare_socket(self):
        # bind multicast UDP listener
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)

        sock.bind(("0.0.0.0", self.server_port))

        mreq = struct.pack("=4sl", socket.inet_aton(self.multicast_address),
                           socket.INADDR_ANY)

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                        self.SOCKET_BUFSIZE)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        logging.info("multicast listener prepared {}:{}".format(self.multicast_address, self.server_port))

        return sock

    def check_incoming(self):
        """Check incoming data."""
        data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)

        try:
            payload = json.loads(data.decode("utf-8"))
            self._handle_data(payload)

        except Exception as e:
            # raise
            logging.error("Can't handle message %r (%r)" % (data, e))

    def _handle_data(self, payload):
        if "cmd" not in payload:
            logging.warning("NOT A COMMAND: {}".format(payload))
            return

        cmd = payload["cmd"]
        sid = None if 'sid' not in payload else payload['sid']

        if cmd == "iam":
            self._handle_iam(payload)
        elif cmd == "heartbeat":
            self._heartbeat(sid, payload['token'] if 'token' in payload else None)
            if "data" in payload:
                self._last_data(sid, ensure_dict(payload['data']))

        elif cmd == "report":
            self._handle_report(payload)

        try:
            logging.debug("data_callback: {}".format(payload))
            if self.data_callback is not None:
                self.data_callback(self, cmd, sid, payload)

        except Exception as e:
            logging.error("Error handle command: {}".format(e))

    def _handle_report(self, payload):
        """
         {'cmd': 'report', 'model': 'magnet', 'sid': '158d00027b4ade', 'short_id': 49810, 'data': '{"status":"close"}'}
        """
        sid = payload['sid']

        if sid not in self._devices:
            self._handle_iam(payload)  # force device discover
        else:
            self._heartbeat(sid)

        self._last_data(sid, ensure_dict(payload['data']))

    def _last_data(self, sid, data):
        if sid not in self._devices:
            logging.warning("data update on non-discovered device sid {}".format(sid))
            return

        dev = self._devices[sid]

        dev["_last_data"] = data

    def _handle_iam(self, payload):
        """
        parse multicast whois-response
        {'cmd': 'iam', 'port': '9898', 'sid': '7c49eb88faaf', 'model': 'gateway', 'proto_version': '1.1.2', 'ip': '192.168.10.8'}
        """

        sid = payload['sid']
        if sid not in self._devices:
            self._devices[sid] = dict()
            logging.info("Auto-discovered device {} sid {} model {}".format(sid, payload['sid'], payload['model']))
            if self.metadata_callback is not None:
                self.metadata_callback(self, sid, payload)

        device = self._devices[sid]

        for field in payload.keys():
            device[field] = payload[field]
        self._heartbeat(sid)

    def _heartbeat(self, sid, token = None):
        if sid not in self._devices:
            logging.warning("heartbeat on non-discovered device sid {}".format(sid))
            return

        self._devices[sid]["_heartbeat_time"] = datetime.datetime.now()
        if token is not None:
            self._devices[sid]["_heartbeat_token"] = token

    # def handle_incoming_data(self, payload):
    #     """Handle an incoming payload, save related data if needed,
    #     and use the callback if there is one.
    #     """
    #     if isinstance(payload.get('data', None), basestring):
    #         cmd = payload["cmd"]
    #         if cmd in ["heartbeat", "report", "read_ack"]:
    #             if self.data_callback is not None:
    #                 self.data_callback(payload["model"],
    #                                    payload["sid"],
    #                                    payload["cmd"],
    #                                    json.loads(payload["data"]))
    #
    #         if cmd == "read_ack" and payload["sid"] not in self._devices:
    #             self._devices[payload["sid"]] = dict(model=payload["model"])
    #
    #         if cmd == "heartbeat" and payload["sid"] not in self._devices:
    #             self.request_sids(payload["sid"])
    #             self._devices[payload["sid"]] = json.loads(payload["data"])
    #             self._devices[payload["sid"]]["model"] = payload["model"]
    #             self._devices[payload["sid"]]["sensors"] = []
    #
    #         if cmd == "get_id_list_ack":
    #             device_sids = json.loads(payload["data"])
    #             self._devices[payload["sid"]]["nodes"] = device_sids
    #
    #             for sid in device_sids:
    #                 self.request_current_status(sid)
    #
    #     if "token" in payload:
    #         self.last_tokens[payload["sid"]] = payload['token']


    # def request_current_status(self, device_sid):
    #     """Request (read) the current status of the given device sid."""
    #     self.send_command_multicast({"cmd": "read", "sid": device_sid})

    def send_command_multicast(self, data):
        """Send a command to the UDP subject (all related will answer)."""
        cmd = json.dumps(data).encode("utf-8")
        logging.debug("send_command: {}".format(cmd))
        self.socket.sendto(cmd,
                           (self.multicast_address, self.multicast_port))

    def send_command_sid(self, sid, data):
        cmd = json.dumps(data).encode("utf-8")
        if sid not in self._devices:
            logging.error("sid {} not found".format(sid))
            return

        dev = self._devices[sid]

        if "model" not in dev and dev["model"] != "gateway":
            logging.error("sid {} is not a gateway".format(sid))
            return

        ip = dev['ip']
        port = int(dev['port'])

        logging.debug("send_command to: {} ({}:{}) {}".format(sid, ip, port, cmd))

        self.socket.sendto(cmd, (ip, port))

    def send_whois(self):
        self.send_command_multicast({"cmd": "whois"})

    def send_get_id_list(self, sid):
        self.send_command_sid(sid, {"cmd": "get_id_list"})

    def get_devices(self):
        """Return the current discovered node configuration."""
        return self._devices


class XiaomiConnectorOld:
    """Connector for the Xiaomi Mi Hub and devices on multicast."""

    MULTICAST_PORT = 4321
    SERVER_PORT = 9898

    MULTICAST_ADDRESS = '224.0.0.50'
    SOCKET_BUFSIZE = 1024

    def __init__(self, data_callback=None, auto_discover=True):
        """Initialize the connector."""
        self.data_callback = data_callback
        self.last_tokens = dict()
        self.socket = self._prepare_socket()

        self.nodes = dict()

    def _prepare_socket(self):
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        sock.bind(("0.0.0.0", self.MULTICAST_PORT))

        mreq = struct.pack("=4sl", socket.inet_aton(self.MULTICAST_ADDRESS),
                           socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                        self.SOCKET_BUFSIZE)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print("multicast socker prepared {}:{}".format(XiaomiConnector.MULTICAST_ADDRESS, XiaomiConnector.MULTICAST_PORT))

        return sock

    def check_incoming(self):
        """Check incoming data."""
        data, addr = self.socket.recvfrom(self.SOCKET_BUFSIZE)

        print("incoming: {}, {}".format(data,addr))

        try:
            payload = json.loads(data.decode("utf-8"))
            print(payload)
            self.handle_incoming_data(payload)

        except Exception as e:
            raise
            print("Can't handle message %r (%r)" % (data, e))

    def handle_incoming_data(self, payload):
        """Handle an incoming payload, save related data if needed,
        and use the callback if there is one.
        """
        if isinstance(payload.get('data', None), basestring):
            cmd = payload["cmd"]
            if cmd in ["heartbeat", "report", "read_ack"]:
                if self.data_callback is not None:
                    self.data_callback(payload["model"],
                                       payload["sid"],
                                       payload["cmd"],
                                       json.loads(payload["data"]))

            if cmd == "read_ack" and payload["sid"] not in self.nodes:
                self.nodes[payload["sid"]] = dict(model=payload["model"])

            if cmd == "heartbeat" and payload["sid"] not in self.nodes:
                self.request_sids(payload["sid"])
                self.nodes[payload["sid"]] = json.loads(payload["data"])
                self.nodes[payload["sid"]]["model"] = payload["model"]
                self.nodes[payload["sid"]]["sensors"] = []

            if cmd == "get_id_list_ack":
                device_sids = json.loads(payload["data"])
                self.nodes[payload["sid"]]["nodes"] = device_sids

                for sid in device_sids:
                    self.request_current_status(sid)

        if "token" in payload:
            self.last_tokens[payload["sid"]] = payload['token']

    def request_sids(self, sid):
        """Request System Ids from the hub."""
        self.send_command({"cmd": "get_id_list", sid: sid})

    def request_current_status(self, device_sid):
        """Request (read) the current status of the given device sid."""
        self.send_command({"cmd": "read", "sid": device_sid})

    def send_command(self, data):
        """Send a command to the UDP subject (all related will answer)."""
        self.socket.sendto(json.dumps(data).encode("utf-8"),
                           (self.MULTICAST_ADDRESS, self.MULTICAST_PORT))

    def get_nodes(self):
        """Return the current discovered node configuration."""
        return self.nodes
