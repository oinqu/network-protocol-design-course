# -*- coding: utf-8 -*-
from Messenger import Messenger
from Heartbeat import Heartbeat
from Config import Config
import select
import sys


class App:
    """
    Main App class.
    Author: Stanislav Grebennik

    Launches the app, initializes Config, Messenger and Heartbeat classes.
    """
    def __init__(self):
        self.config = Config()
        self.messenger = Messenger(self.config)
        self.heartbeat = Heartbeat(self.config, self.messenger)
        self.heartbeat_seconds = self.config.local_getter("heartbeat_seconds")
        self.logger = self.config.get_logger(name=__name__)

    def main(self):
        print("Chat app. Type '!help' for usage information, '!exit' to exit the app.")
        self.logger.info("Chat app is launched")
        self.logger.info(f'Listening for connections on {self.config.root_node.sock}...')

        while True:
            rsocks, wsocks, esocks = select.select(self.config.rlist, [], self.config.rlist, self.heartbeat_seconds)

            if not rsocks and not wsocks:
                self.heartbeat.run_routine()
                continue

            for notified_socket in rsocks:
                if notified_socket == sys.stdin:
                    self.messenger.parse_user_input()

                else:
                    self.messenger.process_incoming_message(notified_socket)
