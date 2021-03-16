#!/bin/bash

cd client
make clean
if [[ $1 = "debug" ]]; then
make debug:=yes
else
make
strip NDNS_client
fi
cd ../server
make clean
if [[ $1 = "debug" ]]; then
make debug:=yes
else
make
fi
