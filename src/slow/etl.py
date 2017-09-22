from rule_chains.frontend import GrokFrontend
from rule_chains import get_names, get_patterns, get_grokit_config
import pytz
import logging


DEFAULT_NAMES = get_names()
DEFAULT_PATTERNS = get_patterns()
GROK_FE = None
DEFAULT_CONFIG = get_grokit_config()
SYSLOG_DISPATCH = 'syslog_dispatcher'


class ETL(object):
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
    def setup_grokker(cls, parser_args):
        patterns_dir = parser_args.cpdir
        config = parser_args.gconfig
        names = parser_args.names
        logging.debug("Loading Grok ETL")
        gr = cls.create_global_gfe(  # default chains configuration
                          config=config,
                          # patterns created for pfsense filterlog and openvpn
                          custom_patterns=patterns_dir,
                          # patterns to load individual groks for
                          names=names)
        logging.debug("Loading Grok ETL completed")
        return gr

    @classmethod
    def get_logstash_server(cls):
        global LOG_STASH_HOST, LOG_STASH_PORT
        return (LOG_STASH_HOST, LOG_STASH_PORT)

    @classmethod
    def get_logstash_connection(cls, uri, queue_name='default'):
        return Connection.create_connection(uri, queue_name)

    @classmethod
    def send_msg(cls, message, uri, queue_name='default'):
        conn = cls.get_logstash_connection(uri, queue_name)
        r = conn.send_msg(message)
        return r, conn

    @classmethod
    def build_grok_etl(cls, config=DEFAULT_CONFIG, names=DEFAULT_NAMES,
                       custom_patterns=DEFAULT_PATTERNS):
        gfe = GrokFrontend(config=config, custom_patterns_dir=custom_patterns,
                           patterns_names=names)
        return gfe

    @classmethod
    def create_global_gfe(cls, config=DEFAULT_CONFIG, names=DEFAULT_NAMES,
                          custom_patterns=DEFAULT_PATTERNS):
        global GROK_FE
        GROK_FE = cls.build_grok_etl(config=config, names=names,
                                     custom_patterns=custom_patterns)
        return GROK_FE

    @classmethod
    def syslog_et(cls, syslog_msg,
                  exclude_results=['SYSLOG_PRE', 'SYSLOG_PRE_MSG']):
        global GROK_FE
        my_fe = GROK_FE
        if my_fe is None:
            my_fe = cls.build_grokit()
        # 'syslog_app_dispatch'
        try:
            fe_results = my_fe.execute_dispatch_table(SYSLOG_DISPATCH,
                                                      syslog_msg)
            if fe_results['outcome']:
                return fe_results['rule_results']
        except:
            pass

        fe_results = my_fe.match_runall_patterns(syslog_msg)
        for n, v in fe_results.items():
            if n in exclude_results:
                continue
            if v is not None and 'rule_results' in v and \
               len(v['rule_results']) > 0:
                return v
        return {}

    @classmethod
    def format_timestamp(cls, tstamp):
        global MY_TZ
        local_tz = MY_TZ.localize(tstamp, is_dst=None)
        utc_tz = local_tz.astimezone(pytz.utc)

        tz_str = utc_tz.strftime("%Y-%m-%dT%H:%M:%S")
        tz_str = tz_str + ".%03d" % (tstamp.microsecond / 1000) + "Z"
        return tz_str
