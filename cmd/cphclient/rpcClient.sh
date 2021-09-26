#!/bin/bash

cp -rf ./../../crypto/bls/lib/mac/*     ./../../crypto/bls/lib/
cp -rf ./../../pow/ethash/randomX/lib/Darwin/*   ./../../pow/ethash/randomX/
go build ./rpcClient.go

cp -rf ./../../crypto/bls/lib/linux/*     ./../../crypto/bls/lib/
cp -rf ./../../pow/ethash/randomX/lib/Linux/*   ./../../pow/ethash/randomX/
