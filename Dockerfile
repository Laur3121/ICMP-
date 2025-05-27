FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    linux-headers-$(uname -r) \
    clang \
    llvm \
    libbpf-dev \
    python3-bpfcc  # PythonからBPFを使うなら

