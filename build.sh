#!/bin/bash

#dynamic key
MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
LENGTH="32"
while [ "${n:=1}" -le "$LENGTH" ]
do
    KEY="$KEY${MATRIX:$(($RANDOM%${#MATRIX})):1}"
    let n+=1
done
#echo "$KEY"

cd client
make clean
if [[ $1 = "debug" ]]; then
make debug:=yes aeskey:="$KEY"
else
make aeskey:="$KEY"
strip NDNS_client
fi
cd ../server
make clean
if [[ $1 = "debug" ]]; then
make debug:=yes aeskey:="$KEY"
else
make aeskey:="$KEY"
fi
