# -*- coding: utf-8 -*-


class Heartbeat:
    """
    Heartbeat class.
    Author: Stanislav Grebennik

    The method run_routine() from this class is called from the main App class with the configured interval.
    Here the app checks for not acked packages and resends them,
    verifies incoming messages and makes sure the entire message is received,
    sends periodic routing updates to the neighbours,
    checks for neighbours connection statuses.
    """
    def __init__(self, config, messenger):
        self.config = config
        self.messenger = messenger
        self.update_heartbeat_frequency = self.config.local_getter("update_heartbeat_frequency")
        self.nodes_online_check_heartbeat_frequency = self.config.local_getter("nodes_online_check_heartbeat_frequency")
        self.message_resend_heartbeat_frequency = self.config.local_getter("message_resend_heartbeat_frequency")
        self.message_resend_tries = self.config.local_getter("message_resend_tries")
        self.message_receive_check_heartbeat_frequency = self.config.local_getter("message_receive_check_heartbeat_frequency")
        self.message_receive_expired_heartbeats = self.config.local_getter("message_receive_expired_heartbeats")
        self._msg_resend_freq = 1
        self._msg_receive_wait = 1
        self._upd_send_freq = 1
        self.logger = self.config.get_logger(name=__name__)

    def resend_unacked_messages(self):
        """Check and resend outgoing messages that didn't received an ack from destination."""
        if self.messenger.outgoing_messages:
            if self._msg_resend_freq >= self.message_resend_heartbeat_frequency:
                self._msg_resend_freq = 1
                discard = []
                for msg_id, msg in self.messenger.outgoing_messages.items():
                    if msg.retries < self.message_resend_tries:
                        self.logger.info(f"resending message {msg_id}, "
                                         f"tries left: {self.message_resend_tries - msg.retries}")
                        msg.retries += 1
                        for segment, packet in msg.cache.items():
                            header_list, payload_list = self.messenger.get_lists_from_packet(packet)
                            src = self.config.root_node.name
                            dst = header_list[1]
                            self.messenger.send_packet_to_dst(src=src, dst=dst, packet=packet)
                    else:
                        self.logger.info(f"{msg_id} outgoing message expired, removing from cache and discarding")
                        discard.append(msg_id)
                for msg_id in discard:
                    del self.messenger.outgoing_messages[msg_id]
            else:
                self._msg_resend_freq += 1

    def check_incoming_messages(self):
        """Check for all not fully received messages and delete the expired ones."""
        if self.messenger.incoming_messages_expiration:

            # Increase messages expiration number by one each heartbeat
            for msg_id, exp in self.messenger.incoming_messages_expiration.items():
                self.messenger.incoming_messages_expiration[msg_id] += 1

            # Decide whether to do something or skip this heartbeat
            if self._msg_receive_wait < self.message_receive_check_heartbeat_frequency:
                self._msg_receive_wait += 1
            else:
                discard = []
                for msg_id, exp in self.messenger.incoming_messages_expiration.items():
                    # If messages expiration number exceeds configured maximum, it gets discarded.
                    if exp >= self.message_receive_expired_heartbeats:
                        self.logger.info(f"{msg_id} incoming message expired, removing from cache and discarding")
                        discard.append(msg_id)
                for msg_id in discard:
                    del self.messenger.incoming_messages[msg_id]
                    del self.messenger.incoming_messages_expiration[msg_id]
                self._msg_receive_wait = 1

    def send_update_to_neighbours(self):
        """Dend periodic routing updates to all neighbours."""
        if self._upd_send_freq < self.update_heartbeat_frequency:
            self._upd_send_freq += 1
        else:
            for node in self.config.root_node.neighbours:
                # If node is online then the entire known routing table is being sent.
                if node.online:
                    self.logger.info(f"node {node.name} is online")
                    self.messenger.send_update_to_neighbours(self.messenger.generate_update_message())
                # If node is offline then the routing table consisting of only this node is being sent.
                else:
                    self.logger.info(f"node {node.name} is offline")
                    self.messenger.send_update_to_neighbours(self.messenger.generate_update_message(node), node.name)
            self._upd_send_freq = 1

    def check_offline_nodes(self):
        """
        Check for offline nodes.

        It has been decided during the protocol designing phase that any node should
        be considered online if we receive a periodic routing update packet from it.
        Otherwise, if we haven't got any routing updates from a node (or any other
        packet for that matter) for an amount of heartbeats configured in
        'nodes_online_check_heartbeat_frequency', the node is considered to be offline.
        """
        self.logger.debug(f"checking for offline nodes")
        for node_name, node in self.config.known_nodes.items():
            node.heartbeats_from_last_update += 1

            if node.heartbeats_from_last_update >= self.nodes_online_check_heartbeat_frequency and node.online:
                # Remove sock from my config
                self.config.remove_socket(node.sock)

                # Reset node config
                node.online = False
                node.sock = None
                node.version = 1
                self.config.root_node.increase_version()
                self.messenger.send_update_to_neighbours(self.messenger.generate_update_message())
                print(f"{node.name} is offline")

    def run_routine(self):
        self.resend_unacked_messages()
        self.check_incoming_messages()
        self.send_update_to_neighbours()
        self.check_offline_nodes()
