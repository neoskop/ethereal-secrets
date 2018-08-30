# Ethereal Secrets

A middleware to help secure temporary confidential data in the browser.

## Overview

_Ethereal Secrets_ is a small set of projects to enable clients to store sensitive data in their browser encrypted. Currently it encompasses the following project parts:

1. [Middleware](./middleware): An Express middleware to expose a REST endpoint to issue secrets or to store encrypted data. The keys and the cipher texts are stored in a Redis DB. Each entry in the database is assigned a time-to-live.
2. [Server](./server): A simple Express server that showcases the usage and can be used as a standalone backend.
3. [Client](./client): A TypeScript/JavaScript library that abstracts the communication with the server.

## Functionality

_Ethereal Secrets_ can either be used to encrypt and store data locally ([local mode](#local-mode)) or to store encrypted data for later retrieval on the server ([remote mode](#remote-mode)). 

### Local Mode

The main purpose of the local mode is to enable end-users to resume their work in a web app even after reloading the page. This is what happens under the hood:

#### Store the data away

1. The client makes a GET request to the server endpoint
2. The server replies with a securely-generated random key along with a session cookie
3. The client uses the key to encrypt the data symmetrically and stores is in the local or session storage

#### Access the data again

1. To retrieve the data again the client again makes a GET request to the server endpoint - this time with the session cookie from the server
2. The server returns the key when the session hasn't expired yet, otherwise a new key and a new session cookie would be returned
3. The client tries to use the key to decrypt the data and returns it on success

### Remote Mode

The purpose of the remote mode is to enable end-users to store their work in a web app and access it on a different device by transferring the key. This is what happens under the hood:

#### Store the data away

1. The client generates a secret locally and encrypts the data symetrically
2. The client posts the ciphertext to the server endpoint
3. The server returns an access key
4. The client stores the access key and local secret

#### Access the data again

1. To retrieve the data again the client again makes a GET request to the server endpoint with the access key as the path
2. The server returns the ciphertext if the access key exists
3. The client decrypts the ciphertext with the local secret

## License

This project is under the terms of the Apache License, Version 2.0. A [copy of this license](LICENSE) is included with the sources.
