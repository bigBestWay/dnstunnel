#!/bin/sh
cd client
make clean
make
cd ../server
make clean
make
