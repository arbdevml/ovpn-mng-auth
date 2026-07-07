#!/usr/bin/env python3


import yaml
import logging
import socket
import sys
import os
import time
import base64
import errno
import uuid
import re
import secrets
import requests


log_level = logging.INFO

log_file = '/var/log/openvpn-auth.log'

# User token validity - since we'll use tokens after the first auth, let's give it a validity - in secondy
user_auth_token_validity = 36000

CONNECT = 1
REAUTH = 2
ESTABLISHED = 3
ADDRESS = 4
DISCONNECT = -1

# RegExp for matching valid username chars
username_regex = re.compile(r'([a-zA-Z0-9_@\-]+)')
num_regex = re.compile('([0-9]+)')

class OvpnAuth(object):
    """OpenVPN client-auth via the management interface"""

    def __init__(self):
        """Initializes the unix socket for communicating with the server."""

        self.saved_user = None
        self.user = None
        self.new_client = None
        self.common_name = None
        self.set_defaults()

        with open('./config.yml', encoding='utf8') as file:
          cfg = yaml.load(file, Loader=yaml.FullLoader)

        if cfg:
          self.url_auth = cfg['auth_url']
          self.token_auth = cfg['auth_token']
          self.ovpn_mng_ip = cfg['ovpn_mng_ip']
          self.ovpn_mng_port = cfg['ovpn_mng_port']
        else:
          logging.info(f'cannot find the config: ./config.yml')
          sys.exit(0)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _socket_send(self, command):
         if sys.version_info[0] == 2:
             self.sock.send(command)
         else:
             self.sock.send(bytes(command, 'utf-8'))

    def _socket_recv(self, length):
        if sys.version_info[0] == 2:
            return self.sock.recv(length)
        else:
            return self.sock.recv(length).decode('utf-8')

    def auth_req(self, common_name='', username='', password='', otp='', ip=''):

        logging.info(f'common_name: {common_name},'
                     f'username: {username}, '
                     f'password: {password}, '
                     f'otp: {otp}, '
                     f'ip: {ip}')
        # self.ckid
        try:
            data = {
                  'common_name':  common_name,
                  'username':     username,
                  'password':     password,
                  'otp':          otp,
                  'ip':           ip,
                  'token':        self.token_auth
            }
            response = requests.post(self.url_auth, data=data, timeout=10)  # , verify=False)
            # Store JSON data in API_Data
            api_data = response.json()


            message = api_data["message"]
            flag    = api_data["status"]

            logging.info(f'FROM server: {api_data}/{message}/{flag}')

            try:
                user_cleaned = username_regex.match(username).group(0)
            except AttributeError:
                user_cleaned = []

            self.user = "".join(user_cleaned)
            current_state = self.user + '|' + str(uuid.uuid4())

            self.states[self.user] = current_state + '|' + password

            b64_user = base64.b64encode(self.user.encode("utf-8")).decode("utf-8")

            if 'True' == str(flag):
                self.user_tokens[self.user] = {}
                self.user_tokens[self.user]["token"] = secrets.token_urlsafe()
                self.user_tokens[self.user]["timestamp"] = time.time()
                msg = 'client-auth ' + ' '.join(self.ckid) + "\r\n"
                msg += 'push "auth-token ' + self.user_tokens[self.user]["token"] + '"\r\n'
                msg += "END"
                reason = None
            elif 'otp' == str(message):
                logging.info(f'self.states[self.user]: {self.states[self.user]}')
                msg = None
                reason = ('CRV1:R,E:' + current_state + ':' + b64_user + ':'
                          + 'Welcome ' + username + '! Enter Authenticator Code, please:')
            else:
                msg = None
                reason = message
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.debug(
              f'error type:{exc_type},file_name:{fname}, line_number:{exc_tb.tb_lineno}, an exception occurred {error}')
            msg = None
            reason = 'Wrong server answer, could you try again letter, please'

        logging.info(f'auth_req return : {msg}/{reason}')
        return msg, reason

    def set_defaults(self):
        self.new_client = 0
        self.user = ''
        self.common_name = ''
        self.saved_user = ''
        self.passwd = ''
        self.user_ip = ''
        self.ckid = ("-1", "-1")

    def connect(self):
        # Connect to the management interface. Waits if the server is not up
        connected = False
        while not connected:
            try:
                self.sock.connect((self.ovpn_mng_ip, self.ovpn_mng_port))
                # if non-blocking is set, than the logic of socket reading must be changed a bit!
                self.sock.setblocking(True)
                connected = True
                # use file interface for reading line by line
                self.sfd = self.sock.makefile('r')  # was r+ but that's not supported in python 3.6
                self.sfdw = self.sock.makefile('w')
                try:
                  socket_data = self._socket_recv(1024)
                  logging.info(socket_data)                      
                  socket_data = self._socket_recv(1024)
                  logging.info(f'\r\nCheck if SUCCESS: \r\n[{socket_data}]\r\n')
                  if socket_data.startswith('SUCCESS: password is correct\r\n'):
                    logging.info('SUCCESS: password is correct')
                  else:
                    logging.info('Failed to auth')
                    sys.exit(0)
                except Exception as e:
                  logging.info(e)
                logging.info('[{}] Connected.'.format(os.getpid()))
            except OSError as exc:
                if exc.errno == errno.EISCONN:
                    return
            except Exception as e:
                logging.debug(e)
                time.sleep(1)
                self.sock.close()
            finally:
                if not connected:
                    time.sleep(1)
                self.sock.close()
                self.__init__()

    def run(self):
        # Parse messages from server and process when a new client connects

        self.states = dict()
        self.user_tokens = dict()
        while True:
            logging.info('Initiating connection')
            self.connect()
            while True:
                try:
                    line = self.sfd.readline()
                    logging.info('line: %s' % line)
                except socket.timeout as e:
                    logging.debug(f"Exception: {e}")
                    logging.debug("Sock timeout")
                    time.sleep(0.25)
                    continue
                except socket.error as e:
                    logging.debug(f"Exception: {e}")
                    logging.debug("Socket error")
                    break
                except Exception as e:
                    logging.debug(f"Exception: {e}")
                    logging.debug("[{}] Exception - can be from interrupt!".format(os.getpid()))
                    break
                if not line:
                    # non-blocking read! Sleep some then reprocess
                    # time.sleep(0.05)
                    # continue
                    break
                line = line.rstrip()
                line_strip = re.sub(r'password=.*', 'password=[...]', line)
                logging.info('got: %s' % line_strip)
                if not line.startswith(">CLIENT:"):
                    continue
                line = line[8:]
                if not line:
                    continue
                words = line.split(',')

                # this will omit password parts
                # logging.debug('split into: %s' % ' '.join(words))

                if words[0] == 'CONNECT' and len(words) == 3:
                    self.ckid = words[1:]
                    logging.info('New client {} {}'.format(words[1], words[2]))
                    self.new_client = CONNECT
                    self.user = ''
                    self.passwd = ''
                    self.user_ip = ''
                    self.common_name = ''
                elif words[0] == 'REAUTH' and len(words) == 3:
                    self.ckid = words[1:]
                    logging.info('New client (reauth) {} {}'.format(words[1], words[2]))
                    self.new_client = REAUTH
                    self.user = ''
                    self.passwd = ''
                    self.user_ip = ''
                    self.common_name = ''
                elif words[0] == 'ESTABLISHED' and len(words) == 2:
                    self.new_client = ESTABLISHED
                    logging.info('Client {} connection ESTABLISHED'.format(words[1]))
                elif words[0] == 'DISCONNECT' and len(words) == 2:
                    self.new_client = DISCONNECT
                    logging.info('Client {} DISCONNECTED'.format(words[1]))
                elif words[0] == 'ADDRESS':
                    self.new_client = ADDRESS
                    logging.info('Client {} associated subnet {} - {}'.format(words[1], words[2], words[3]))
                elif line.startswith('ENV,END') and self.new_client:
                    if self.new_client == CONNECT or self.new_client == REAUTH:
                        logging.info('Processing new client')
                        self.process_client()
                    elif self.new_client == ADDRESS:
                        logging.info("ADDRESS END")
                    elif self.new_client == ESTABLISHED:
                        logging.info("User {}/{} is now CONNECTED.".format(self.user, self.user_ip))
                    elif self.new_client == DISCONNECT:
                        logging.info("Cleanup after {}".format(self.user))
                        # don't free it up, we'll need it upon next connect
                        # self.states.pop(self.user,'None')
                        # self.rad_attrs.pop(self.user,'None')
                    self.new_client = 0
                elif not self.new_client or not words[0] == 'ENV' or len(words) < 2:
                    continue

                # Processing ENV variables
                if words[1].startswith('username='):
                    self.user = words[1][9:]
                    logging.debug('got user = %s' % self.user)
                elif words[1].startswith('common_name='):
                    self.common_name = words[1][12:]
                    logging.debug(f'got common_name = {self.common_name}')
                elif words[1].startswith('password='):
                    self.passwd = words[1][9:]
                    logging.debug('got pass = [...]')
                elif words[1].startswith('untrusted_ip='):
                    self.user_ip = words[1][13:]
                    logging.debug('got user_ip = %s' % self.user_ip)

            try:
                if self.sfd:
                    self.sfd.close()
                if self.sfdw:
                    self.sfdw.close()
                if self.sock:
                    self.sock.close()
            except Exception as e:
                logging.debug(f"Exception: {e}")
                logging.debug('Failed to close instances')
                pass
            # exit gracefully
            sys.exit(0)

    def process_client(self):
        # Verify dynamic challenge response or prompt a new challenge

        reason = 'User/Password/Token is in invalid format'
        msg = ''

        try:
            user_cleaned = username_regex.match(self.user).group(0)
        except AttributeError:
            user_cleaned = []

        self.user = "".join(user_cleaned)
        current_state = self.user + '|' + str(uuid.uuid4())

        if self.new_client == REAUTH:
            # TODO: fixme - lehet, hogy nem lesz jo, mert auth-nocache van
            # lehet, hogy kene bele egy 12h limit vagy hasonlo!!
            # we should check just the username/password, not the OTP
            if len(self.passwd) == 43 and "CRV" not in self.passwd:
                logging.debug("Got auth-token: {}".format(self.passwd))
            # ez valsz csak egy benezes miatt van benne... majd tesztelni kell, de szinte kizart, hogy kene
            if len(self.passwd) >= 40 and '/' in self.passwd:
                logging.debug("Splitting self.passwd by /")
                auth_token, user_passwd = self.passwd.split('/')
            else:
                auth_token = self.passwd
            # van valid token?
            if self.user_tokens.get(self.user) is None or self.user_tokens[self.user].get("token") is None:
                reason = "No stored valid token found."
                logging.info("No stored valid token found for {}".format(self.user))
            elif self.user_tokens[self.user]["token"] != auth_token:
                reason = "Invalid token value."
                logging.info("Invalid token value for user {}.".format(self.user))
                logging.debug(
                    "Invalid token value for user {} [{}/{}]."
                    .format(self.user, self.user_tokens[self.user]["token"],
                                                                      auth_token))
            elif (self.user_tokens[self.user]["timestamp"] + user_auth_token_validity) <= time.time():
                expired_secs = time.time() - self.user_tokens[self.user]["timestamp"] - user_auth_token_validity
                reason = "User token has expired."
                logging.info("User token has expired {}s ago for {}".format(expired_secs, self.user))
            elif self.user_tokens[self.user]["token"] == auth_token and (
                    self.user_tokens[self.user]["timestamp"] + user_auth_token_validity) > time.time():
                msg = 'client-auth-nt ' + ' '.join(self.ckid)
                pending_validity = self.user_tokens[self.user]["timestamp"] + user_auth_token_validity - time.time()
                logging.info(
                    'Client reauth ({}/{}): valid token found [still valid for {}s]'
                    .format(self.user, self.user_ip,
                                                                                            pending_validity))
            else:
                reason = "Unknown faliure upon token validation"
                logging.debug("Unkown failure upon token validation. {} != {} TS: {} Time: {} Validity time: {}"
                .format(
                    auth_token, self.user_tokens[self.user]["token"], self.user_tokens[self.user]["timestamp"],
                    time.time(), user_auth_token_validity))

        elif not self.user:
            reason = 'Empty username'

        # Static-challenge mode, but we can reply with a dynamic challenge

        elif self.passwd.startswith('SCRV1:') and self.passwd[6:]:
            logging.info('Received static-challenge from {}/{}'.format(self.user, self.user_ip))
            pr64 = self.passwd[6:].split(':')
            p = ''
            r = ''
            if pr64[0]:
                p = base64.b64decode(pr64[0]).decode("utf-8")
            if len(pr64) == 2 and pr64[1]:
                r = base64.b64decode(pr64[1]).decode("utf-8")
            logging.debug("Received PASS length {}".format(len(p)))
            logging.debug("Received OTP TOKEN {}".format(r))

            try:
                r_cleaned = num_regex.match(r).group(0)
            except AttributeError:
                r_cleaned = ''

            if r_cleaned != r:
                if len(r_cleaned) == 8:
                    r = r_cleaned
                else:
                    r = None

            msg, reason = self.auth_req(self.common_name, self.user, p, r, self.user_ip)

        elif self.passwd.startswith('CRV1::') and self.passwd[6:]:
            # logging.info('Received dynamic-challenge from {}/{}'.format(self.user,self.user_ip))
            # Response to dynamic challenge received.
            # Expect CRV1::state_id::answer
            # The correct answer is embedded in the state_id of the challenge
            # we just check that it matches response.

            p = self.passwd[6:].split('::')
            logging.info('Received dynamic-challenge from {}/{}/{}'.format(self.user, self.user_ip, p))
            logging.info('self.states[self.user]: {}'.format(self.states[self.user]))

            # logging.debug(p)
            if len(p) == 2:
                state_id, recvd_response = p
                p = state_id.split('|')
                if len(p) == 2:
                    recvd_user, recvd_uuid = p
                else:
                    recvd_user, recvd_uuid = ('', '')
            else:
                recvd_user, recvd_uuid, recvd_response = ('', '', '')

            logging.info(f'recvd_uuid={recvd_uuid}, recvd_username={recvd_user}, recvd_response={recvd_response}')

            if self.states[self.user]:
                logging.info(self.states[self.user])
            else:
                logging.info("NO STATE INFO for user '{}'".format(self.user))

            sstate = self.states[self.user].split('|')
            # this will emit user passwords!
            logging.debug(sstate)

            if len(sstate) == 3:
                expected_user, expected_uuid, saved_passwd = sstate
            else:
                expected_user, expected_uuid, saved_passwd = ('', '', '')

            try:
                r_cleaned = num_regex.match(recvd_response).group(0)
            except AttributeError:
                r_cleaned = ''

            if r_cleaned != recvd_response:
                if len(r_cleaned) == 8:
                    recvd_response = r_cleaned
                else:
                    recvd_response = None

            if not recvd_response or not recvd_uuid or not recvd_user:
                reason = 'Dynamic respose in invalid format'
            elif recvd_uuid != expected_uuid:
                logging.info(f'recvd_uuid != expected_uuid: {recvd_uuid}/{expected_uuid}')
                reason = 'Wrong security token with dynamic response'
            elif self.user != recvd_user or expected_user != recvd_user:
                reason = 'Wrong username with dynamic response'
            else:
                msg, reason = self.auth_req(self.common_name, self.user, saved_passwd, recvd_response, self.user_ip)

        else:
            msg, reason = self.auth_req(self.common_name, self.user, self.passwd, '', self.user_ip)
        if not msg:
            logging.info("Access DENIED to {}/{} with reason '{}'".format(self.user, self.user_ip, reason))
            msg = ('client-deny ' + ' '.join(self.ckid) + ' reason "' + reason + '"')
        else:
            logging.info('Access ACCEPT to {}/{}'.format(self.user, self.user_ip))

        try:
            msg = msg + '\r\n'
            self.sfdw.write(msg)
            self.sfdw.flush()

        except Exception as e:
            logging.debug(e)
            return

        logging.debug('replied: %s' % msg)
        self.set_defaults()

if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_file)
    stream_handler = logging.StreamHandler()
    stream_formatter = logging.Formatter('%(asctime)-15s %(levelname)-8s %(message)s')
    file_formatter = logging.Formatter(
      "{'time':'%(asctime)s', 'name': '%(name)s', \
      'level': '%(levelname)s', 'message': '%(message)s'}"
    )
    file_handler.setFormatter(file_formatter)
    stream_handler.setFormatter(stream_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.addHandler(logging.StreamHandler(sys.stdout))
    auth_handler = OvpnAuth()
    logging.info("Startup completed, starting connection to OpenVPN socket")
    auth_handler.run()
