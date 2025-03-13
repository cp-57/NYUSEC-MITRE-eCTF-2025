#! /bin/bash
cd deployment;
python create_global_secrets.py;
cd ..;
make DECODER_ID=${DECODER_ID};
rm ./inc/secrets.h;
cp build/max78000.elf build/max78000.bin /out;