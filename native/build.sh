#!/bin/sh

gcc -c *.c -I /opt/homebrew/include/

ar rcs libstdxcj.a *.o

rm *.o

mv libstdxcj.a ../
