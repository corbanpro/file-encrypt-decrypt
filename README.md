# Secrets

CLI tool to encrypt/decrypt file.

## installation

```
bash ./build-install.sh
```

## usage

```
enc [OPTIONS] <read file> [write file]
```

- options: `-d` for decrypt
- read file: file to read
- write file: file to write

## example

```
enc README.md README.md.enc
enc -d README.md.enc README.md
```
