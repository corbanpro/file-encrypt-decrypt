#!bin/bash

cargo build
sudo mv ./target/debug/file-encrypt-decrypt /usr/local/bin/enc
