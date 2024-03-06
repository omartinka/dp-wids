#! /usr/bin/env python3

import managers

from analyze.wids import Wids
from utils.arguments import parse_args

import utils.context as ctx
import time, sys

def main():
    arg_parser = parse_args()
    managers.init()
 
    wids = Wids()
    return wids.run()

if __name__ == '__main__':
    exit(main())
