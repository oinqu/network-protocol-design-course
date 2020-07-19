# -*- coding: utf-8 -*-
import libnacl.sealed
import libnacl.public


class Node:
    """
    Node object.
    Author: Stanislav Grebennik

    This class represents a single node. The class is used for describing all known nodes
    including ourselves. It stores all information about a node and a list of routes,
    which tell us how to connect and send a message to this node.

    Node can store multiple routes leading to it, which can be used for altering packets
    path in case some primary connection is lost.

    Each node has its own crypto box, which is initialized from nodes public key and which
    is used for encrypting and decrypting payloads.
    https://libnacl.readthedocs.io/en/latest/topics/sealed.html#creating-box

    The protocol specification states that the public key needs to be obtained manually.
    Nodes public keys should be present in a configuration file.
    """
    def __init__(self, **kwargs):
        self.name = kwargs.get("name")
        self.ip = kwargs.get("ip")
        self.port = kwargs.get("port")
        self.private = kwargs.get("private")
        self.public = kwargs.get("public")
        self.neighbours = kwargs.get("neighbours", list())
        self.sock = kwargs.get("sock", None)
        self.version = kwargs.get("version", 0)
        self.online = kwargs.get("online", False)
        self.heartbeats_from_last_update = 0
        self.routes = list()
        self.crypto_box = self.init_crypto_box()

    def init_crypto_box(self):
        """
        Initialize crypto box.

        If the private key is present, then use key pair for initializing the box.

        :return: libnacl SealedBox
        """
        if self.public and self.private:
            skey = libnacl.public.SecretKey(bytes.fromhex(self.private))
            pkey = libnacl.public.PublicKey(bytes.fromhex(self.public))
            return libnacl.sealed.SealedBox(skey, pkey)
        elif self.public:
            pkey = libnacl.public.PublicKey(bytes.fromhex(self.public))
            return libnacl.sealed.SealedBox(pkey)
        return None

    def increase_version(self):
        """
        Increase the version number of the routing tree.

        The protocol states that in order to overcome the number overflow, the version number
        should be reset back to the beginning of the scale.
        """
        if self.version == 99999:
            self.version = 1
        else:
            self.version += 1

    def add_route(self, route):
        """
        Adding a route to the nodes routes list.

        This method checks for duplicates, too. It should be noted that a route
        which starts with the same first hop but has different weight is not considered
        as a duplicate.

        The nodes list is sorted after each addition, so that the first route in the list
        is always the best possible route to the node.

        :param route:
        :return:
        """
        duplicate_found = False
        if self.routes:
            for r in self.routes:
                if r.first_node == route.first_node and r.weight == route.weight:
                    duplicate_found = True

        if not duplicate_found:
            self.routes.append(route)
            self.sort_routes()

    def sort_routes(self):
        """Sort routes list, best possible routes first."""
        tmp = self.routes.copy()
        self.routes = []
        while True:
            route = None
            weight = None
            for r in tmp:
                if weight:
                    if weight > r.weight:
                        weight = r.weight
                        route = r
                else:
                    weight = r.weight
                    route = r
            self.routes.append(route)
            tmp.remove(route)
            if not tmp:
                break
