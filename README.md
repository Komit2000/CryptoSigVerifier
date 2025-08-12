# CryptoSigVerifier
Pro tool for crypto signatures
# CryptoSigVerifier v2
Pro tool for ECDSA signatures with Ethereum support.

Features:
- Key gen, sign, verify
- Perf tests
- Error handling

Installation:
pip install -r requirements.txt

Usage:
python sig_verifier.py --mode example

Tests: python sig_verifier.py --mode test

Docker: docker build -t cryptosig . ; docker run cryptosig
