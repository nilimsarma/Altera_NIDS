#!/bin/bash
set -e -x
export CL_CONTEXT_EMULATOR_DEVICE_ALTERA=1
cd device
aoc -g -v -march=emulator snort.cl
cp snort.aocx ../bin/snort.aocx

cd ..
make clean
make

./bin/snort_opencl
