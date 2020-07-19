# -*- coding: utf-8 -*-


class Route:
    """
    Route object.
    Author: Stanislav Grebennik

    Each route to the node consists only from the first hop destination, which is
    always our direct neighbours node object, and routes weight.

    The protocol doesn't define whether we should store and use the entire
    routes to the desired destination. So this implementation is storing only
    the first hop the packet should be sent to.

    We don't have to store the entire route because all the other nodes know which
    node has to be the first hop to forward the packet to. Despite that we still
    know the entire topology, which can be obtained from node objects in Config
    classes known_nodes dictionary.
    """
    def __init__(self, first_node, weight=1):
        self.first_node = first_node
        self.weight = weight
