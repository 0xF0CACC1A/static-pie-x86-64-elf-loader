#!/usr/bin/env sh
gcc test.c -static-pie -fPIE -pthread -o test
