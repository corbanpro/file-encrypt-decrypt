#!bin/bash

cargo build
sudo mv ./target/debug/secrets /usr/local/bin/
