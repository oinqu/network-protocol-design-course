# -*- coding: utf-8 -*-
import sys

HELP_MENU_FILE = "data/menu"


class Options:
    """
    Options class.
    Author: Stanislav Grebennik

    This is a menu class for the console application.
    """
    def __init__(self, config):
        self.config = config

    def get_help(self):
        """Help menu"""
        try:
            with open(HELP_MENU_FILE, "r") as file:
                print(file.read())
        except FileNotFoundError:
            return print("Menu file location is not found. Make sure you are running the app from project root dir.")

    def get_online_nodes(self):
        """Show only online nodes."""
        online_nodes = self.config.get_online_nodes()
        if not online_nodes:
            print("no one is online right now")
        else:
            for node in online_nodes:
                print(node.name)

    def get_offline_nodes(self):
        """Show only offline nodes."""
        offline_nodes = self.config.get_offline_nodes()
        if not offline_nodes:
            print("no one is offline right now")
        else:
            for node in offline_nodes:
                print(node.name)

    def get_all_nodes(self):
        """Show all known nodes"""
        for node in self.config.known_nodes:
            print(node)

    def exit(self):
        print("exiting...")
        sys.exit(1)

    def parse_input(self, input_option):
        """Helper method, which helps validating users input."""
        possible_options = ["help", "online", "offline", "all", "exit"]

        for option in possible_options:
            if option in input_option.lower():
                return option
        return None

    def get_option(self, input_option):
        """Validate users input and call the correct menu."""
        option = self.parse_input(str(input_option))
        if option == "help":
            self.get_help()
        elif option == "online":
            self.get_online_nodes()
        elif option == "offline":
            self.get_offline_nodes()
        elif option == "all":
            self.get_all_nodes()
        elif option == "exit":
            self.exit()
        else:
            print(f"unknown option '{input_option}', try '!help'")
