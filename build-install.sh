#!bin/bash

cargo build
sudo mv ./target/debug/bitwarden_backup /usr/local/bin/bwback
