# -*- coding: utf-8 -*-
from Message import Message
from Options import Options
from Route import Route
from Node import Node
import logging
import hashlib
import base64
import errno
import math
import uuid
import sys
import os


class Messenger:
    """
    Messenger class.
    Author: Stanislav Grebennik

    This is the main messenger engine of the chat application.
    """
    def __init__(self, config):
        self.config = config
        self.options = Options(self.config)
        self.incoming_messages = dict()
        self.incoming_messages_expiration = dict()
        self.outgoing_messages = dict()
        self.files_dir = self.config.local_getter("files_dir")
        self.packet_payload_size_bytes = self.config.local_getter("packet_payload_size_bytes")
        self.max_packet_hops = self.config.local_getter("max_packet_hops")
        self.buffer_size = self.config.local_getter("buffer_size")
        self.encoding = self.config.local_getter("encoding")
        self.logger = self.config.get_logger(name=__name__, level=logging.DEBUG)

    def process_incoming_message(self, sock):
        """
        Get the payload type and receive incoming packet data from a socket.
        Forward the packet if it isn't belong to us.

        :param sock: socket to read packet data from
        """
        addr, msg = self.receive_packet(sock)

        # Remove socket if client gracefully closed the connection
        if not len(msg):
            self.config.remove_socket(sock)
            return

        dst, ack = False, False
        try:
            header_list, payload_list = self.get_lists_from_packet(msg)
            hop_count = int(header_list[2])
            src = header_list[0]
            dst = header_list[1]

            if hop_count >= self.max_packet_hops:
                self.logger.warning(f"hop count exceeded set maximum {self.max_packet_hops}, dropping packet")

            elif dst != self.config.root_node.name:
                self.logger.info(f"received message for someone else ({dst}), forwarding... msg: {msg}")
                hop_count = hop_count + 1
                header_list[2] = str(hop_count)
                self.logger.info(f"hop count increased to {hop_count}")

                packet = self.get_packet_from_lists(header_list, payload_list)
                self.send_packet_to_dst(src=src, dst=dst, packet=packet)

            else:
                self.logger.info(f"receiving message addressed to me: {msg}")

                # If we received a packet from a node and we don't have its address info,
                # add the ip, port and route into the nodes configuration.
                # Rewrite nodes address only if it is not manually defined in our config file.
                if src in self.config.known_nodes:
                    if "ip" not in self.config.global_getter[src] and "port" not in self.config.global_getter[src]:
                        self.config.known_nodes[src].ip = addr[0]
                        self.config.known_nodes[src].port = addr[1]
                    if not self.config.known_nodes[src].routes:
                        route = Route(self.config.known_nodes[src])
                        self.config.known_nodes[src].routes.append(route)
                # Add the node to our neighbours list if it isn't there yet.
                if self.config.known_nodes[src] not in self.config.root_node.neighbours:
                    self.config.root_node.neighbours.append(self.config.known_nodes[src])

                segment_type = header_list[3]
                if segment_type == 'SEGMENT':
                    dst, ack = self.parse_message_segment(header_list, payload_list)

                elif segment_type == 'ACK':
                    self.parse_message_ack(header_list)

                else:
                    self.logger.warning(f"unknown packet segment type: {segment_type}")

        except Exception as e:
            self.logger.warning(f"could not get segmentation type from incoming packet")
            self.logger.warning(e)

        # Send an ack back to the source node.
        if dst and ack:
            self.logger.info(f"sending an ack to {dst}")
            self.send_packet_to_dst(src=self.config.root_node.name, dst=dst, packet=ack)

    def receive_packet(self, sock):
        """
        Receive the incoming packet data from socket.

        :param sock: socket to read packet data from
        :return: address and message
        """
        try:
            while True:
                msg, addr = sock.recvfrom(self.buffer_size)
                return addr, msg

        except IOError as e:
            # EAGAIN or EWOULDBLOCK is being thrown when no incoming data is detected, application can
            # continue its work as usual. Otherwise there is some IOError problem which must be examined.
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                self.logger.critical(f"Reading error: {e}")

        except Exception as e:
            self.logger.critical(f"Very unexpected message occured during receiving a packet: {e}")

    def get_lists_from_packet(self, raw_msg):
        """
        Get list interpretation of a raw packet data.

        :param raw_msg: encoded bytes
        :return: list for packet header and list for packet payload.
        """
        message_list = raw_msg.decode(encoding=self.encoding).split('|')
        return message_list[:6], message_list[6:]

    def get_packet_from_lists(self, header_list, payload_list):
        """
        Get raw packet bytes from header and payload lists.

        :param header_list: list representing the packet header
        :param payload_list: list representing the packet payload
        :return:
        """
        header_list.extend(payload_list)
        return '|'.join(header_list).encode(encoding=self.encoding)

    def parse_message_segment(self, header_list, payload_list):
        """
        The main message parsing and processing method.

        :param header_list: list representing the packet header
        :param payload_list: list representing the packet payload
        :return: source and an ack packet that should be sent to that source.
                 False and False in case message parsing wasn't successful,
                 this means that packet might be damaged or wrong, waiting to get the packet again.
        """
        # Header
        src = header_list[0]
        dst = header_list[1]
        hop_count = header_list[2]
        segment_type = header_list[3]
        msg_id = header_list[4]
        segment = header_list[5]

        # Payload
        checksum = payload_list[0]
        msg_type = payload_list[1]
        msg = '|'.join(payload_list[2:])

        # Create Message object if it doesn't exist.
        if msg_id not in self.incoming_messages:
            self.incoming_messages[msg_id] = Message(msg_id)
        self.incoming_messages[msg_id].cache[segment] = msg

        if msg_id not in self.incoming_messages_expiration:
            self.incoming_messages_expiration[msg_id] = 1

        if self.check_checksum(checksum, msg):
            if self.incoming_messages[msg_id].is_full():
                self.logger.debug(f"message {msg_id} is fully received! Cache: {self.incoming_messages[msg_id].cache}")

                full_msg = self.incoming_messages[msg_id].get_msg()
                self.logger.debug(f"full message: {full_msg}")

                msg_bytes = base64.b64decode(full_msg.encode(encoding=self.encoding))
                bclear = self.config.root_node.crypto_box.decrypt(msg_bytes)
                decoded_msg = bclear.decode(encoding=self.encoding)

                if msg_type == "CHAT":
                    if decoded_msg.split('|', 1)[0] == "MESSAGE":
                        print(f"{src} > {decoded_msg.split('|', 1)[1]}")
                    else:
                        self.receive_file(decoded_msg.split('|', 1)[1], src)

                if msg_type == "ROUTING":
                    self.process_message_routing(decoded_msg)
                    self.send_update_to_neighbours(
                        msg=decoded_msg,
                        hop_count=int(hop_count) + 1,
                        exclude=src
                    )

                self.logger.debug(f"removing {msg_id} from cache")
                del self.incoming_messages[msg_id]
                del self.incoming_messages_expiration[msg_id]

            # Consider the node online if we received a message from it.
            if src in self.config.known_nodes:
                if not self.config.known_nodes[src].online:
                    self.config.known_nodes[src].online = True
                    self.config.known_nodes[src].heartbeats_from_last_update = 0
                    print(f"{src} is online")

            return src, self.get_ack_packet(dst=src, msg_id=msg_id, segment=segment)
        return False, False

    def check_checksum(self, checksum, payload):
        """
        Check the checksum of an incoming message.

        :param checksum: checksum from the received packet.
        :param payload: payload that the checksum is generated from.
        :return: boolean
        """
        self.logger.debug(f"payload: {payload}, "
                          f"received checksum: {checksum}, "
                          f"our calculated checksum: {hashlib.md5(payload.encode(encoding=self.encoding)).hexdigest()}")
        if checksum == hashlib.md5(payload.encode(encoding=self.encoding)).hexdigest():
            return True
        self.logger.warning(f"checksum check failed")
        return False

    def receive_file(self, file_payload, src):
        """
        Ask the user whether to write the received file to disk, and then do it.

        This approach has its limitations, one of which is that the entire file data is stored
        in memory until its fully received. Disk caching can be implemented in the future releases.

        :param file_payload: the entire data of a file
        :param src: file sender
        """
        file_name = file_payload.split("&", 1)[0]
        file_data = file_payload.split("&", 1)[1]

        validation = input(f"A file '{file_name}' received from {src}. Do you want to save a file to disk? y/n: ")

        if validation.lower() == "y":
            os.makedirs(self.files_dir, exist_ok=True)
            file_full_path = self.files_dir + file_name

            with open(file_full_path, "w") as file:
                file.write(file_data)
            self.logger.info(f"file received: {file_full_path}")
            print(f"The file '{file_name}' is saved to {self.files_dir}")
        else:
            print(f"The file '{file_name}' from {src} is discarded.")

    def process_message_routing(self, msg):
        """
        Process the routing message.

        :param msg: Full routing message
        :return: boolean
        """
        msg_list = msg.split("|")
        node_name = msg_list[0]
        version = int(msg_list[1])
        neighbours_count = int(msg_list[2])
        neighbours = msg_list[3:]

        if node_name in self.config.known_nodes:
            node = self.config.known_nodes[node_name]
            node.heartbeats_from_last_update = 0
            if not node.online:
                node.online = True
                print(f"{node.name} is online")

            # Check version number and validate the neighbours count
            if self.check_version(version, node.version) and neighbours_count == len(neighbours):
                new_discovered_nodes = []
                node.neighbours = []
                node.version = version

                for neighbour in neighbours:
                    neighbour_name = neighbour.split("&")[0]
                    neighbour_weigth = int(neighbour.split("&")[1])

                    # Add each direct neighbour to neighbours list
                    if neighbour_weigth == 1:
                        # Check if node is already known to us
                        if neighbour_name in self.config.known_nodes:
                            node.neighbours.append(self.config.known_nodes[neighbour_name])

                            # Look for all the routes we know to the nodes' direct neighbours
                            if self.config.known_nodes[neighbour_name].routes:
                                for route in self.config.known_nodes[neighbour_name].routes:
                                    # Create new route with new weights if routes first hop doesn't equal
                                    # to the node itself.
                                    if route.first_node != node:
                                        new_route = Route(route.first_node, route.weight + neighbour_weigth)
                                        node.add_route(new_route)
                            else:
                                self.logger.warning(f"did not find any routes leading to "
                                                    f"{self.config.known_nodes[neighbour_name].name}")

                        # If the discovered node is not in our known_nodes dictionary then create a new node
                        elif neighbour_name != self.config.root_node.name:
                            new_node = Node(name=neighbour_name)
                            node.neighbours.append(new_node)
                            self.config.known_nodes[neighbour_name] = new_node
                            new_discovered_nodes.append(new_node)

                # Add routes to newly discovered nodes
                for new_node in new_discovered_nodes:
                    for route in node.routes:
                        new_route = Route(route.first_node, route.weight + 1)
                        new_node.add_route(new_route)

                self.config.root_node.increase_version()
                return True

            else:
                self.logger.info(f"discarding the routing message, version or content doesn't match")
                return False
        else:
            self.logger.info(f"discarding the routing message, node is not found in known_nodes dictionary")
            return False

    def check_version(self, received, existing):
        """
        Check the version of a received routing packet.

        Protocol specification states that update packet with version number significantly lower than
        stored version number should be treated as a valid update packet.

        :param received: received version number (int)
        :param existing: existing version number (int)
        :return: boolean
        """
        if received > existing:
            return True
        if existing > 99900 and received < 100:
            return True
        return False

    def get_ack_packet(self, dst, msg_id, segment):
        """
        Get an ack packet to be sent to dst.

        :param dst: destination of an ack
        :param msg_id: message id
        :param segment: segment number
        :return: encoded packet data
        """
        src = self.config.root_node.name
        output_list = [src, dst, '1', 'ACK', msg_id, segment]
        output_str = '|'.join(output_list)
        self.logger.info(f"ack generated: {output_str}")
        return output_str.encode(encoding=self.encoding)

    def send_update_to_neighbours(self, msg, dst=None, hop_count=1, exclude=None):
        """
        Send a routing update packet to neighbours.

        :param msg: update message
        :param dst: destination. If it isn't defined then update will be sent to all known neighbours.
        :param hop_count: packet hop count.
        :param exclude: some node can be excluded from destinations.
        :return:
        """
        # if destination is not specified, send packet to every node except an excluded one
        if not dst:
            for neighbour in self.config.root_node.neighbours:
                if neighbour.name != exclude:
                    packets = self.get_packets(
                        dst=neighbour.name,
                        msg=msg,
                        msg_type="ROUTING",
                        hop_count=hop_count
                    )

                    for single_packet in packets:
                        self.send_packet_to_dst(
                            src=self.config.root_node.name,
                            dst=neighbour.name,
                            packet=single_packet,
                            force=True
                        )
        else:
            packets = self.get_packets(
                        dst=dst,
                        msg=msg,
                        msg_type="ROUTING",
                        hop_count=hop_count
                    )

            for single_packet in packets:
                self.send_packet_to_dst(
                    src=self.config.root_node.name,
                    dst=dst,
                    packet=single_packet,
                    force=True
                )

    def parse_message_ack(self, header_list):
        """
        Parse a received ack message, delete message from cache if the message is fully acked by receiver.

        :param header_list:
        :return:
        """
        msg_id = header_list[4]
        segment = header_list[5]

        if msg_id in self.outgoing_messages:
            if segment in self.outgoing_messages[msg_id].cache:
                del self.outgoing_messages[msg_id].cache[segment]
            else:
                self.logger.warning(f"{segment} segment is not found in {msg_id} message")

            if self.outgoing_messages[msg_id].is_empty():
                self.logger.info(f"message {msg_id} fully acked by remote receiver")
                del self.outgoing_messages[msg_id]
        else:
            self.logger.info(f"can't find message {msg_id} for received ack, it might have been acked already")

    def parse_user_input(self):
        """Parse user stdin input"""
        msg = sys.stdin.readline().strip()
        if msg != "":
            if msg[0] == "!":
                self.options.get_option(msg[1:])

            elif msg[:2] == ">>":
                self.send_input(msg[2:], "FILE")

            elif msg[0] == ">":
                self.send_input(msg[1:], "MESSAGE")

            else:
                print(f"wrong input, try '!help'")

    def send_input(self, user_input, chat_type):
        """Send user input to defined destination. If 'all' is used as destination then broadcast the message."""
        input_to_list = user_input.split(" ", 1)
        src = self.config.root_node.name
        input_dst = input_to_list[0]
        if len(input_to_list) > 1:
            msg = input_to_list[1]
        else:
            print("Wrong input, please try again")
            return

        dst_list = []
        if input_dst != "all":
            if input_dst in self.config.known_nodes:
                if self.config.known_nodes[input_dst].online:
                    dst_list.append(input_dst)
                else:
                    print("Person is offline, can't send a message right now")
                    return
            else:
                print("Unknown person, please try again")
                return
        else:
            if self.config.get_online_nodes():
                for node in self.config.get_online_nodes():
                    dst_list.append(node.name)
            else:
                print("No one is online right now, can't send a message right now")
                return

        for dst in dst_list:
            if chat_type == "MESSAGE":
                packets = self.get_packets(dst=dst, msg=f"{chat_type}|{msg}", msg_type="CHAT")
            elif chat_type == "FILE":
                file = self.get_file(msg)
                if file:
                    packets = self.get_packets(dst=dst, msg=f"{chat_type}|{file}", msg_type="CHAT")
                else:
                    print(f"File with a name '{msg}' is not found on local disk, please try again")
                    return
            else:
                self.logger.warning(f"unknown chat type: {chat_type}")
                return

            for single_packet in packets:
                self.send_packet_to_dst(src=src, dst=dst, packet=single_packet)
            print("Message is sent.")

    def get_packets(self, dst, msg, msg_type, hop_count=1):
        """
        Get packet with correct segments for msg parameter.

        :param dst: destination
        :param msg: message
        :param msg_type: message type, 'CHAT' or 'ROUTING'
        :param hop_count: hop count
        :return: list of segmented packets
        """
        encoded_msg = msg.encode(encoding=self.encoding)
        encrypted_msg = self.config.known_nodes[dst].crypto_box.encrypt(encoded_msg)
        base64_msg = base64.b64encode(encrypted_msg).decode(encoding=self.encoding)
        self.logger.debug(f"full encrypted msg: {base64_msg}")

        msg_id = self.generate_id(7)
        packets = list()

        segment_total = math.ceil(len(base64_msg) / self.packet_payload_size_bytes)
        segment_counter = 0

        for msg_segment in self.split_message(base64_msg):
            segment_counter += 1
            segment = f"{segment_counter}/{segment_total}"
            segment_packet = self.get_segment_packet(
                dst=dst,
                segment=segment,
                msg_id=msg_id,
                msg=msg_segment,
                msg_type=msg_type,
                hop_count=hop_count
            )
            packets.append(segment_packet)

            if msg_id not in self.outgoing_messages:
                self.outgoing_messages[msg_id] = Message(msg_id)
            self.outgoing_messages[msg_id].cache[segment] = segment_packet

        self.logger.debug(f"packets generated: {packets}")
        self.logger.debug(f"messages in {msg_id} message cache: {self.outgoing_messages[msg_id].cache}")
        return packets

    def generate_id(self, id_length):
        return str(uuid.uuid4())[:id_length]

    def get_file(self, file_name):
        try:
            with open(file_name, "r") as file:
                return f"{file_name.split('/')[-1]}&{file.read()}"
        except FileNotFoundError:
            return None

    def split_message(self, msg):
        for i in range(0, len(msg), self.packet_payload_size_bytes):
            yield msg[i: i + self.packet_payload_size_bytes]

    def get_segment_packet(self, dst, segment, msg_id, msg, msg_type, hop_count):
        checksum = hashlib.md5(msg.encode(encoding=self.encoding)).hexdigest()
        src = self.config.root_node.name
        packet_list = [src, dst, str(hop_count), 'SEGMENT', msg_id, segment, checksum, msg_type, msg]
        packet = '|'.join(packet_list)
        return packet.encode(encoding=self.encoding)

    def send_packet_to_dst(self, src, dst, packet, force=False):
        """
        Send packet to destination.

        :param src: source
        :param dst: destination nodes name
        :param packet: packet data
        :param force: boolean, if set to True then send the packet even if the destination is offline
        """
        if self.config.known_nodes[dst].routes:
            node = self.config.known_nodes[dst].routes[0].first_node

            self.logger.info(f"sending a packet: {packet}, to: {dst}, through: {node.name}")
            self.logger.debug(f"all known routes to the node {dst}: "
                              f"{[route.first_node.name for route in self.config.known_nodes[dst].routes]}")

            # If the best possible route is to send message back to where it came from,
            # then something is wrong, try to look for another route.
            if node.name == src:
                if len(self.config.known_nodes[dst].routes) > 1:
                    node = self.config.known_nodes[dst].routes[1].first_node
                else:
                    self.logger.warning("the only route to destination is to send the packet back to"
                                        "where it came from. Dropping a packet to prevent looping.")
                    node = None

            if node and (self.config.known_nodes[dst].online or force):
                self.send_packet(dst_node=node, packet=packet)
            else:
                self.logger.info(f"outgoing packet to {dst} is dropped, "
                                 f"destination is offline, unknown or no possible route has been found")
        else:
            self.logger.warning(f"no route found to {dst}, dropping the packet")

    def send_packet(self, dst_node, packet):
        """Send a packet to destination, create or reuse existing socket."""
        if not dst_node.sock:
            self.logger.info(f"{dst_node.name} doesn't have a socket, creating...")
            dst_node.sock = self.config.create_socket()
            if self.config.root_node.ip and self.config.root_node.port:
                dst_node.sock.bind((self.config.root_node.ip, int(self.config.root_node.port)))
            self.config.rlist.append(dst_node.sock)
        else:
            self.logger.info(f"reusing known address of {dst_node.name}")

        addr = (dst_node.ip, int(dst_node.port))
        dst_node.sock.sendto(packet, addr)
        self.logger.info(f"packet is successfully sent to {dst_node.name} {addr}")

    def generate_update_message(self, init_node=None):
        """
        Generate periodic update message, which is going to be sent to the neighbours.
        This method is currently used only in Heartbeat class.

        :param init_node: if the init_node is specified then generate the packet for only to this node,
                          even if the node is offline. Otherwise generate packets for every known online node.
        :return: plain text packet data
        """
        out_list = [
            self.config.root_node.name,
            str(self.config.root_node.version),
        ]

        if init_node:
            out_list.append("1")
            out_list.append(f"{init_node.name}&{init_node.routes[0].weight}")
        else:
            out_list.append(str(len(self.config.get_online_nodes())))
            for node_name, node in self.config.known_nodes.items():
                if node.online and node.routes:
                    out_list.append(f"{node_name}&{node.routes[0].weight}")
        return '|'.join(out_list)
