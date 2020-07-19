# -*- coding: utf-8 -*-


class Message:
    """
    Message object.
    Author: Stanislav Grebennik

    This class represents an incoming or outgoing message. Each message is stored in memory
    as a separate object.

    Main purpose of this class is to be a cache for message segments. The cache can be used in case
    of outgoing messages for waiting acks from destination, or in case of incoming messages
    for waiting until the message has been fully transmitted. Then the object is deleted.
    """
    def __init__(self, msg_id):
        self.msg_id = msg_id
        self.retries = 0
        self.cache = dict()

    def is_full(self):
        """
        Check whether the messages cache contains all segments.

        Used for checking incoming messages.
        """
        total_segments = int(next(iter(self.cache)).split('/')[1])
        if len(self.cache) == total_segments:
            return True
        return False

    def is_empty(self):
        """
        Check whether the messages cache is empty.

        Used for checking outgoing messages.
        The outgoing messages segment gets deleted after receiving an ack from destination.
        So an empty cache is seen as a successfully sent message.
        """
        if self.cache == {}:
            return True
        return False

    def get_msg(self):
        """Compile a message from segments stored in cache."""
        out = []
        total_segments = int(next(iter(self.cache)).split('/')[1])
        for current_segment in range(total_segments):
            segment_str = f"{current_segment + 1}/{total_segments}"
            out.append(self.cache[segment_str])
        return ''.join(out)
