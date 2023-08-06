#! /usr/bin/env bash

make clean
make
sudo setcap cap_net_raw+eip ./wids-sensor
