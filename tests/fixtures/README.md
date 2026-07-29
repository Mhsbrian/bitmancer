# Interop fixtures

`legacy_private_envelope.json` is a real BitChat private envelope, captured from
release 733098bb and carried here from upstream's own test suite
(`bitchatTests/Nostr/Fixtures/`). It is not synthetic: it was produced by a
different implementation, so decrypting it proves interoperability rather than
self-consistency.

Recipient private key: `8355a5c110cdfef2e644f4ad5d51c39f253b2c2c80ebb6856379fb16531dc1fa`
Expected plaintext:    `legacy fixture from 733098bb`
Expected sender:       `2e3d79df7047204f02b726c574e256f8de1dd80510f7dcb8b0d12df13acb87e6`

The key is published in upstream's fixtures and protects nothing; it exists so
this envelope can be opened by anyone checking a client against it.
