# -*- coding: utf-8 -*-
from Route import Route
from Node import Node
import configparser
import logging
import socket
import sys
import os

CONFIG_FILE = "app.ini"
LOCAL_CONFIG_NAME = "CONFIG"


class Config:
    """
    Config class.
    Author: Stanislav Grebennik

    This class loads information from configuration file about itself as a node in a routing topology,
    all neighbours defined in configuration file and holds discovered information about other nodes in topology.
    """
    def __init__(self):
        self.global_getter = self.init_getter()
        self.default_logging_location = self.local_getter("log_file")
        self.logger = self.get_logger(name=__name__)
        self.root_node = Node(
            name=self.local_getter("username"),
            ip=self.local_getter("ip"),
            port=self.local_getter("port"),
            public=self.local_getter("public"),
            private=self.local_getter("private"),
            version=1,
            neighbours=self.get_local_neighbours()
        )
        self.rlist = [sys.stdin]
        self.root_node.sock = self.init_root_sock()
        self.known_nodes = self.init_known_nodes()
        self.known_sockets = {}

    def init_root_sock(self):
        """Initialize socket for myself if my ip and port are known"""
        if self.root_node.ip and self.root_node.port and self.local_getter("limit"):
            sock = self.create_socket()
            try:
                sock.bind((self.local_getter("limit"), int(self.root_node.port)))
            except Exception as e:
                self.logger.critical(f"socket binding failed with an error: {e}")
                print("Can't use the address or a port defined in configuration file.")
                sys.exit(1)
            self.rlist.append(sock)
            return sock
        return None

    def init_getter(self):
        """
        Initialize configuration parser.

        :return: pre-configured ConfigParser() instance
        """
        getter = configparser.ConfigParser()
        getter.read(CONFIG_FILE)
        return getter

    def local_getter(self, parameter):
        """
        Get value from 'LOCAL_CONFIG_NAME' section of config file.

        This method helps to get applications configuration values even from the other classes,
        where no information about config file location and ConfigParser is present.

        :param parameter: variable name under 'LOCAL_CONFIG_NAME' section of config file
        :return: value from config file
        """
        if parameter in self.global_getter[LOCAL_CONFIG_NAME]:
            out_value = self.global_getter[LOCAL_CONFIG_NAME][parameter]
            try:
                return int(out_value)
            except ValueError:
                return out_value
        else:
            return None

    def get_local_neighbours(self):
        """
        Get list of current neighbours visible in configuration file.

        :return: list with current neighbours
        """
        neighbours = list()
        for node in self.global_getter.items():
            if node[0] != "DEFAULT" and node[0] != LOCAL_CONFIG_NAME:
                name = node[0]
                n = Node(name=name, public=self.global_getter[name]["public"])

                if "ip" in self.global_getter[name]:
                    n.ip = self.global_getter[name]["ip"]

                if "port" in self.global_getter[name]:
                    n.port = self.global_getter[name]["port"]

                # Direct neighbours are considered to be the nodes with known ip and port
                if n.ip and n.port:
                    n.routes.append(Route(n))
                    neighbours.append(n)
        return neighbours

    def init_known_nodes(self):
        """
        Initialise the dictionary with all known nodes.

        This method adds all nodes present in configuration file in known_nodes dictionary.

        :return: known_nodes dictionary where key is node name
                 and value is Node object containing all information about a node.
        """
        known_nodes = {}
        # Add neighbours first
        for node in self.root_node.neighbours:
            known_nodes[node.name] = node

        # Then check for all the other nodes specified in ini file.
        # You can specify a node in ini file only with its public key, the ip and port are not mandatory
        for node in self.global_getter.items():
            if node[0] != 'DEFAULT' and node[0] != LOCAL_CONFIG_NAME:
                name = node[0]
                if name not in known_nodes and "public" in self.global_getter[name]:
                    known_nodes[name] = Node(name=name, public=self.global_getter[name]["public"])

        return known_nodes

    def create_socket(self):
        """
        Helper method that creates and preconfigures the socket.

        :return: socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def remove_socket(self, sock):
        """
        Remove known socket from everywhere.

        :param sock: socket that needs to be removed.
        :return:
        """
        self.logger.info(f"Closed connection")

        if sock and sock != self.root_node.sock:

            if sock in self.rlist:
                self.rlist.remove(sock)

            for user, user_socket in self.known_sockets.items():
                if user_socket == sock:
                    del self.known_sockets[user]

    def get_online_nodes(self):
        """
        Get a list of currently online nodes.

        :return:
        """
        return [self.known_nodes[node] for node in self.known_nodes if self.known_nodes[node].online]

    def get_offline_nodes(self):
        """
        Get a list of currently offline nodes.

        :return:
        """
        return [self.known_nodes[node] for node in self.known_nodes if not self.known_nodes[node].online]

    def get_logger(self, **kwargs):
        """
        Helper method, that initializes, configures and returns a logger.

        If called from other class, logger will have a name of that class it was called from.
        That way we can initialize a separate logger with different options and levels
        for different classes.

        :param kwargs: name= name.
                       level= desired level.
                       out= location for output log file on local disk.
        :return: logger
        """
        name = kwargs.get("name", __name__)
        level = kwargs.get("level", logging.DEBUG)
        output_location = kwargs.get("out", self.default_logging_location)
        os.makedirs(output_location.rsplit("/", 1)[0], exist_ok=True)

        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        output_logger = logging.getLogger(name)
        file_handler = logging.FileHandler(output_location)
        file_handler.setFormatter(formatter)
        output_logger.addHandler(file_handler)
        output_logger.setLevel(level)
        return output_logger
