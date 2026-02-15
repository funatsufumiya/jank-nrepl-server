#!/bin/bash

cd `dirname $0`
cd cpp

if [ -n "$MSYSTEM" ]; then
  clang++ -lws2_32 -shared -o libsimplesocket.dll -lz simple_socket_wrapper.cpp
elif [ "$(uname)" == "Darwin" ]; then
  clang++ -shared -o libsimplesocket.dylib -lz simple_socket_wrapper.cpp
else
  clang++ -shared -o libsimplesocket.so -lz simple_socket_wrapper.cpp
fi
