import logging
import argparse
import sys

from slow.hitter import HitterService as Hitter
from slow.hitter import KnownHosts

logging.getLogger().setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
ch.setFormatter(formatter)
logging.getLogger().addHandler(ch)

parser = argparse.ArgumentParser(description='Start syslog-grok-mongo captures.')

parser.add_argument('-name', type=str, default=Hitter.NAME,
                    help='name of the service')
#  Mongo configs
parser.add_argument('-muri', type=str, default=None,
                    help='mongo user password')
parser.add_argument('-mdb', type=str, default=None,
                    help='mongo db name')

#  ETL stuff
parser.add_argument('-cpdir', type=str, default=DEFAULT_PATTERNS,
                    help='directory containing custom grok patterns directory')
parser.add_argument('-names', type=str, default=DEFAULT_NAMES,
                    help='file containing all the names for rule patterns')
parser.add_argument('-gconfig', type=str, default=DEFAULT_CONFIG,
                    help='Grok frontend configuration for rule chains')

#  Hitter stuff
parser.add_argument('-broker_uri', type=str, default=Hitter.BROKER_URI,
                    help='kombu queue address')
parser.add_argument('-broker_queue', type=str, default=Hitter.BROKER_QUEUE,
                    help='kombu queue name to publish to')
parser.add_argument('-buffer_uri', type=str, default=Hitter.BROKER_URI,
                    help='buffer uri for results')
parser.add_argument('-buffer_queue', type=str, default=Hitter.LOGSTASH_QUEUE,
                    help='kombu queue for results')
parser.add_argument('-known_hosts', type=str, default=KnownHosts.HOST_FILE,
                    help='hosts file to load')


V = 'log levels: INFO: %d, DEBUG: %d, WARRNING: %d' % (logging.INFO,
                                                       logging.DEBUG,
                                                       logging.WARNING)
parser.add_argument('-log_level', type=int, default=logging.DEBUG,
                    help=V)


def setup_known_hosts(parser_args):
    global KNOWN_HOSTS
    known_hosts = parser_args.known_hosts
    if known_hosts is not None:
        logging.debug("Loading known hosts")
        data = open(known_hosts).read()
        for line in data.splitlines():
            if len(line.strip()) == 0:
                continue
            ip, host = line.strip().split()
            KNOWN_HOSTS[ip] = host
        logging.debug("Loading known hosts completed")


if __name__ == "__main__":
    args = parser.parse_args()

    mongo_backend = MongoConnection(args.mhost, args.mport,
                                    args.muser, args.mpass,
                                    args.mdb)
    etl_backend = ETL.setup_grokker(args)

    service = Hitter(broker_uri=args.broker_uri,
                     broker_queue=args.broker_queue,
                     hosts_file=args.known_hosts,
                     mongo_backend=mongo_backend,
                     etl_backend=etl_backend,
                     store_uri=args.buffer_uri,
                     store_queue=args.buffer_queue)

    try:
        logging.debug("Starting the syslog listener")
        service.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        raise
