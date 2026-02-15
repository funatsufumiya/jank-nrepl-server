#!/bin/bash

cd `dirname $0`
cd cpp

clang++ -lws2_32 -shared -o libsimplesocket.dll -lz simple_socket_wrapper.cpp