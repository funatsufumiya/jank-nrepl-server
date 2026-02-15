#!/bin/bash

cd `dirname $0`
cd cpp

if [ -n "$MSYSTEM" ]; then
  clang++ -lws2_32 -shared -o libsimplesocket.dll -lz simple_socket_wrapper.cpp
else
  clang++ -lws2_32 -shared -o libsimplesocket.dll -lz simple_socket_wrapper.cpp
fi
