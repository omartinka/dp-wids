import argparse
import utils.context as ctx
from modules import available
from utils.config import config

def parse_args():
    p = argparse.ArgumentParser(
        description="wids"
    )
    p.add_argument(
        '-m', '--mode',
        help='mode',
        type=int,
    )
    p.add_argument(
        '-i', '--trace-file', 
        help='trace file to analyze',
    )
    p.add_argument(
        '-r', '--remote',
        help='address(/es) of remote log collecting software, split by `,`',
    )
    p.add_argument(
        '-o', '--output-file',
        help='path to a file where to write logs',
    )
    p.add_argument(
        '-v', '--log-verbose',
        action='store_true',
        help='print generated alerts to stdout',
    )
    p.add_argument(
        '-c', '--config',
        help='path to config file',
    )
    p.add_argument(
        '-l', '--list-modules',
        action='store_true',
        help='list installed (not enabled!) detection modules'
    )

    args = p.parse_args()
    
    # If config file is specified, load it.
    if args.config is not None:
        config.init(args.config)
        config.load()
    
    # Override all specified params
    if args.trace_file:
        config.trace_file      = args.trace_file 
    
    if args.mode:
        config.mode            = args.mode
    
    if args.output_file:
        config.output_file     = args.output_file
    
    if args.log_verbose:
        config.verbose         = args.log_verbose
    
    if args.list_modules:
        # TODO import modules and print the list that is there
        print('Available modules:', ', '.join(available))
        exit(0)
        pass

    # Parse remote addresses
    if args.remote is not None:
        _remotes = []

        for _r in args.remote.strip().split(','):
            _tmp = _r.strip().split(':')
            _remote = {'addr': _tmp[0], port: int(_tmp[1])}
        
        config.load_remote(_remote)

    if config.mode == ctx.MODE_NONE:
        p.print_usage()
        exit(-1)
    
    if config.debug:
        config.summary()

    return p
