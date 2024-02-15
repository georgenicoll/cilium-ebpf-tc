#!/bin/bash
SCRIPT_DIR=$(dirname "$0")
pushd "$SCRIPT_DIR" || exit 99
../remove-filters-and-qdisc.sh
go generate
go build -o packet-monitor.out main.go tc_bpfel.go
sudo ./packet-monitor.out
../remove-filters-and-qdisc.sh
popd || exit 99