#!/bin/bash

openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature0.sign toBeSignedTxt/attestationStringParty0.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature1.sign toBeSignedTxt/attestationStringParty1.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature2.sign toBeSignedTxt/attestationStringParty2.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature3.sign toBeSignedTxt/attestationStringParty3.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature4.sign toBeSignedTxt/attestationStringParty4.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature5.sign toBeSignedTxt/attestationStringParty5.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature6.sign toBeSignedTxt/attestationStringParty6.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature7.sign toBeSignedTxt/attestationStringParty7.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature8.sign toBeSignedTxt/attestationStringParty8.txt
openssl dgst -sha256 -sign attestationPrivateKey.pem -out signatures/signature9.sign toBeSignedTxt/attestationStringParty9.txt
