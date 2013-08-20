#!/usr/bin/env sh

clang -ggdb fuse-mine.c `pkg-config fuse --cflags --libs` -o fuse-mine
