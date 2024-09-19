# Secrets

CLI tool to encrypt/decrypt file.

## installation

```
bash ./build-install.sh
```

## usage

```
enc <action> <read file> <write file>
```

- action: `-e` for encrypt, `-d` for decrypt
- read file: file to read
- write file: file to write

## example

```
enc -e README.md README.md.enc
enc -d README.md.enc README.md
```
