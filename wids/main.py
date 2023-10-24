#! /usr/bin/env python3

import managers
import managers.filestream
import managers.receiver

from utils.arguments import parse_args

import utils.context as ctx
import time, sys

def main():
    parse_args()
    managers.init()

    if ctx.mode == ctx.MODE_TRACE:
        managers.filestream.file_stream.process(ctx.trace_file)
    else:
        managers.receiver.data_receiver.run()


if __name__ == '__main__':
    main()
