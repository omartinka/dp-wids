import argparse
import utils.context as ctx

def parse_args():
    p = argparse.ArgumentParser(
        description="wids"
    )
    p.add_argument(
        '-i', '--trace-file', 
        help='trace file to analyze',
        default=None
    )
    p.add_argument(
        '-l', '--logstash',
        help='address of logstash input where to send alerts',
        default=None
    )
    p.add_argument(
        '-lp', '--logstash-port',
        help='port of logstash input where to send alerts'
    )
    p.add_argument(
        '-of', '--output-file',
        help='path to a file where to write logs',
        default=None
    )
    p.add_argument(
        '-v', '--log-verbose',
        help='print generated alerts to stdout',
        default=False
    )
    p.add_argument(
        '-c', '--config',
        help='path to config file',
        default=None
    )

    args = p.parse_args()
    
    if args.config is not None:
        ctx.load_config_from_file(args.config)

    ctx.trace_file = args.trace_file 
    ctx.mode = ctx.MODE_TRACE if ctx.trace_file else ctx.MODE_REALTIME
    ctx.elastic_addr = args.logstash
    ctx.elastic_port = int(args.logstash_port) if args.logstash_port else None
    ctx.output_file = args.output_file
    ctx.verbose_logging = args.log_verbose

