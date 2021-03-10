#!/bin/sh
cd client
make clean
if [ $1 = "debug" ]; then
make debug:=yes
else
make
fi
cd ../server
make clean
if [ $1 = "debug" ]; then
make debug:=yes
else
make
fi
