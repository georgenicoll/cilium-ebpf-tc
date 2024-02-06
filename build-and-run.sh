#!/bin/bash
go generate
go build -o a.out main.go tc_bpfel.go
sudo ./a.out
