#!/bin/bash

echo '["0x'
xxd -p signatures/signature0.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature1.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature2.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature3.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature4.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature5.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature6.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature7.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature8.sign | tr -d \\n
echo '","0x'
xxd -p signatures/signature9.sign | tr -d \\n
echo '"]'
