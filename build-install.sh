#!/bin/bash

cargo build --release
cp ./target/release/enc ~/.local/bin/
