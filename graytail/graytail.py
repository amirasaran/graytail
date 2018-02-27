#!/usr/bin/env python
# encoding=utf8
import sys

import argparse
import getpass
import re
from operator import itemgetter

import natsort as natsort
import requests
import time

from requests.auth import HTTPBasicAuth

if sys.version_info[0] < 3:
    reload(sys)
    sys.setdefaultencoding('utf8')

VERSION = "1.0.0"


class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @classmethod
    def colorize(cls, text, color):
        return color + text + cls.ENDC

    @classmethod
    def warning(cls, text):
        return cls.colorize(text, cls.WARNING)

    @classmethod
    def fail(cls, text):
        return cls.colorize(text, cls.FAIL)

    @classmethod
    def success(cls, text):
        return cls.colorize(text, cls.OKGREEN)

    @classmethod
    def info(cls, text):
        return cls.colorize(text, cls.OKBLUE)

    @classmethod
    def header(cls, text):
        return cls.colorize(text, cls.HEADER)

    @classmethod
    def underline(cls, text):
        return cls.colorize(text, cls.UNDERLINE)

    @classmethod
    def bold(cls, text):
        return cls.colorize(text, cls.BOLD)


def main():
    print("############################################################################")
    print("#                                                                          #")
    print("# Welcome to graylog tail                                                  #")
    print("# Version: {}                                                           #".format(VERSION))
    print("# Python version: {}.{}.{}                                                    #".format(sys.version_info[0],
                                                                                                   sys.version_info[1],
                                                                                                   sys.version_info[2]))
    print("#                                                                          #")
    print("############################################################################")
    try:
        parser = argparse.ArgumentParser(description='Gray log command line tail')

        parser.add_argument(
            '--base-url',
            dest='base_url',
            help='Gray log base url',
            type=str,
            required=True
        )

        parser.add_argument(
            '--username',
            dest='username',
            help='The user username in gray log',
            type=str,
            required=True
        )

        parser.add_argument(
            '--password',
            dest='password',
            help='The user password',
            type=str,
            default="",
            required=False
        )

        args = parser.parse_args()

        url = "{}/api/api-browser".format(args.base_url)
        try:
            response = requests.get(url)
            if 'X-Graylog-Node-ID' not in response.headers:
                print(BColors.fail("The base-url is not valid"))
                exit()

        except Exception as e:
            print(BColors.fail("SERVER NOT FOUND \nThe request timeout!"))
            exit()

        if args.password == "":
            args.password = getpass.getpass('Password:')

        def get_stream():
            url = "{}/api/streams".format(args.base_url)
            response = requests.get(url, auth=HTTPBasicAuth(args.username, args.password))
            if response.status_code != 200:
                print(BColors.fail('Your login credential is not valid'))
                exit()

            result = response.json()
            print(BColors.header("\n\nPlease select on of the following list to show tail"))
            result['streams'] = natsort.natsorted(result['streams'], key=itemgetter(*['description']))
            for index, stream in enumerate(result['streams']):
                print("[{}] {}".format(index + 1, stream['description']))

            while True:
                try:
                    stream_index = int(
                        input(BColors.info('Enter stream number[1 - {}]: '.format(len(result['streams'])))))
                except ValueError as e:
                    print(BColors.warning("Invalid input id"))
                    continue

                if stream_index == 0 or stream_index > len(result['streams']):
                    print(BColors.warning("The requested stream not found"))
                    continue

                return result['streams'][stream_index - 1]

        regex = r"\[pid: \d{1,3}\|app: \d\|req: \d{1,4}\/\d{1,4}\]" \
                r" \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} \(.*\) \{\d{1,2} vars in \d{1,20} bytes} "

        def replace(data):
            return re.sub(regex, '', data)

        def xrange(a, b):
            i = a - 1
            while i <= b:
                i += 1
                yield i

        def start_stream(stream_id):
            url = "{}/api/search/universal/relative".format(args.base_url)

            querystring = {
                "query": "*",
                "range": "300",
                "decorate": "true",
                "filter": "streams:{}".format(stream_id)
            }

            headers = {
                'accept': "application/json",
            }

            last_item = []
            while True:
                time.sleep(1)
                response = requests.get(url, headers=headers, params=querystring,
                                        auth=HTTPBasicAuth(args.username, args.password))
                result = response.json()
                messages = result['messages']
                for message in messages:
                    if message['message']['_id'] in last_item:
                        continue

                    print("{}".format(replace(message['message']['message'])[1:-1]))
                    last_item.append(message['message']['_id'])

        stream_data = get_stream()
        print(BColors.success("****************************************************************"))
        print(BColors.success("# {} ".format(stream_data['description'])))
        print(BColors.success("****************************************************************"))
        start_stream(stream_data["id"])
    except KeyboardInterrupt as e:
        print(BColors.warning('\nStopping process .....'))
