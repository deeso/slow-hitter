from hashlib import sha256
from datetime import datetime
from .etl import ETL
from .connection import Connection
from kombu.mixins import ConsumerMixin

from tzlocal import get_localzone
import json
import time
import pytz
import socket

import logging
import os


class KnownHosts(object):
    HOST_FILE = "/etc/hosts"

    def __init__(self, filename=HOST_FILE):
        self.filename = filename
        try:
            os.stat(self.filename)
        except:
            raise

        self.mapping = self.read_hosts_file(filename)

    @classmethod
    def read_hosts_file(cls, filename):
        mapping = {}
        for line in open(filename).readlines():
            if line.strip() == '':
                continue
            elif line.strip().find('#') == 0:
                continue
            elif len(line.split()) < 2:
                continue

            l = line.strip()
            ip = l.split()[0]
            host_names = l.split()[1:]
            if len(host_names) == 0:
                continue

            #  FIXME this means the expected mapping[ip] = host
            #  may not be right
            ip_host_mappings = [(ip, h) for h in host_names]
            for ip, host in ip_host_mappings:
                mapping[host.strip()] = ip.strip()
                mapping[ip.strip()] = host.strip()
        return mapping

    def is_ip(self, ip):
        # FIXME track down a regex and use that
        d = ip.split('.')
        if len(d) != 3:
            return False
        if not all([i.isdigit() for i in d]):
            return False
        if not all([int(i, 10) >= 0 for i in d]):
            return False
        if not all([int(i, 10) <= 255 for i in d]):
            return False
        return True

    def resolve_host(self, ip_host):
        if ip_host in self.mapping and \
           not self.is_ip(ip_host):
            return self.mapping[ip_host]
        name = ip_host
        try:
            name, _, _ = socket.gethostbyname(ip_host)
            self.mapping[ip_host] = name
            self.mapping[name] = ip_host
        except:
            name = ip_host
            self.mapping[ip_host] = name
        return name


class HitterService(ConsumerMixin):
    NAME = 'processor'
    BROKER_URI = "redis://127.0.0.1:6379"
    BROKER_QUEUE = "mystified-catcher"
    KNOWN_HOSTS = KnownHosts()
    LOGSTASH_QUEUE = "logstash-results"
    SYSLOG_MSG_TYPE = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFORMATIONAL",
        7: "DEBUG",
    }

    def __init__(self, broker_uri=BROKER_URI, broker_queue=BROKER_QUEUE,
                 hosts_file=None, mongo_backend=None,
                 etl_backend=ETL, msg_limit=100,
                 #  leaving it open to use kombu to buffer messages
                 logstash_uri=BROKER_URI,
                 logstash_queue=LOGSTASH_QUEUE):

        if hosts_file is not None:
            self.KNOWN_HOSTS = KnownHosts(filename=hosts_file)

        self.broker_uri = broker_uri
        self.queue = broker_queue
        self.logstash_uri = logstash_uri
        self.logstash_queue = logstash_queue

        self.conn = Connection.create_connection(broker_uri, broker_queue)
        x = Connection.create_connection(logstash_uri, logstash_queue)
        self.logstash_conn = x

        self.mongo_backend = mongo_backend
        self.etl_backend = etl_backend
        self.keep_running = False
        self.msg_limit = msg_limit

    @classmethod
    def split_alert_message(cls, data):
        t = ''
        msg = data
        end = data.find('>')
        start = data.find('<')
        if len(data) < end+1:
            return '', msg
        if start == 0 and end > 0 and end < 10:
            t = data[start+1:end]
            if not t.isdigit():
                return '', data
            else:
                msg = data[end+1:]
        return t, msg

    @classmethod
    def calculate_msg_type(cls, data):
        t, msg = cls.split_alert_message(data)
        if len(t) == 0:
            return "UNKNOWN"
        v = int(t, 10)
        if v > 7:
            v &= 0x7
        return cls.SYSLOG_MSG_TYPE[v]

    @classmethod
    def format_timestamp(self, tstamp, catcher_tz_str):
        catcher_tz = pytz.timezone(catcher_tz_str)
        local_tz = catcher_tz.localize(tstamp, is_dst=None)
        utc_tz = local_tz.astimezone(pytz.utc)

        return utc_tz.strftime("%Y-%m-%dT%H:%M:%S") +\
            ".%03d" % (tstamp.microsecond / 1000) + "Z"

    @classmethod
    def get_base_json(cls, syslog_msg, syslog_server_ip,
                      catcher_name, catcher_tz):
        r = {'source': "syslog", 'raw': syslog_msg,
             'type': 'json',
             '_id': sha256(syslog_msg).hexdigest(),
             '@timestamp': cls.format_timestamp(datetime.now(), catcher_tz),
             '@version': "1",
             'message': "transformed syslog",
             'path': '',
             'tags': [],
             }
        t, msg = cls.split_alert_message(syslog_msg)
        r['syslog_level'] = cls.calculate_msg_type(syslog_msg)
        r['syslog_msg'] = msg
        r['syslog_tag'] = t
        r['syslog_server'] = cls.resolve_host(syslog_server_ip)
        r['syslog_server_ip'] = syslog_server_ip
        r['syslog_catcher'] = catcher_name
        return r

    @classmethod
    def resolve_host(cls, ip_host):
        return cls.KNOWN_HOSTS.resolve_host(ip_host)

    def process_message(self, syslog_msg, syslog_server_ip,
                        catcher_name, catcher_tz):
        m = "Extracting and converting msg from %s msg (syslog: %s)" % (syslog_server_ip, catcher_name)
        logging.debug(m)
        r = self.get_base_json(syslog_msg, syslog_server_ip, catcher_name)
        sm = {}
        try:
            result = self.etl_backend.syslog_et(syslog_msg)
            sm.update(result.get('rule_results', result))
            if 'rule_name' in result:
                sm['rule_name'] = result.get('rule_name')
            sm['tags'] = []
            if sm.get('syslog_level', None) is not None:
                sm['tags'].append(sm['syslog_level'])
            if sm.get('rule_name', None) is not None:
                sm['tags'].append(sm['rule_name'])
        except:
            pass
        r.update(sm)
        return r

    def send_results(self, syslog_msg, etl_data):
        if self.mongo_backend is not None:
            m = "Sending results to mongo"
            logging.debug(m)
            raw_insert, json_insert = self.mongo_backend.insert(
                                                                syslog_msg,
                                                                etl_data)
            if not raw_insert:
                logging.debug("Failed to insert the raw syslog information in mongo")
            if not json_insert:
                logging.debug("Failed to insert the processed syslog information in mongo")

        m = "Sending results to logstash"
        logging.debug(m)
        if not self.logstash_conn.send_msg(etl_data):
            logging.debug("Failed to send the logs to logstash")

    def process_and_report(self, message_str):
        logging.debug("Processing and report syslog_msg")
        try:
            message = json.loads(message_str)
        except:
            raise
        syslog_msg = message.get('syslog_msg', '')
        syslog_server_ip = message.get('syslog_server_ip', '')
        catcher_name = message.get('catcher_name', '')
        catcher_tz = message.get('catcher_tz', get_localzone())

        etl_data = self.process_message(syslog_msg,
                                        syslog_server_ip,
                                        catcher_name, catcher_tz)
        self.send_results(syslog_msg, etl_data)

    def read_messages(self):
        msgs = self.conn.read_messages(cnt=self.msg_limit,
                                       callback=self.process_and_report)
        return msgs

    def serve_forever(self, poll_interval=1.0):
        self.keep_running = True
        while self.keep_running:
            try:
                self.read_messages()
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                break
