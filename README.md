# Handshake implementation of RLPx

This library is a implementation of handshake part of RLPx described in details here:

https://github.com/ethereum/devp2p/blob/master/rlpx.md

RLPx is one of the protocols used by ethereum. It is used to send and synchronize data between nodes. Data can include block, transactions etc.

As a reference implementation official go ethereum and akula was used:
https://github.com/ethereum/go-ethereum
https://github.com/akula-bft/akula


# What is implemented

1. Initial handshake method `auth`
2. Verification of received `ack` along with confirmation of keys
3. Hello message, both encoding and decoding in RLP format
4. Verification of authenticity via MAC calculation


# Dependencies:

1. tokio
2. aes and ctr
3. rlp
4. secp256k1
5. sha2 and sha3

# Testing

There are two types of tests prepared, first are the unit tests. They check if various parts of the code are correct. Additionally you can launch main program with enode parameter like: `enode://....@127.0.0.1:30303` from any node that runs geth. You can either startup local geth or find public node here https://ethernodes.org/nodes

## Unit Test
run `cargo test`

## Connection Test
Connection tests establishes actual connection with eth node and performs a handshake. 

After connecting initial handshake that consist of `auth` and `hello` message along with MAC authentication is performed.

Example output with successful handshake:
```
Connecting to 195.201.207.37:30303
Remote public key 024a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c
Connected!
Received valid ack
Received hello message:
Protocol Version: 5,
Remote public key: 024a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c
Client Version: Geth/v1.10.25-stable-69568c55/linux-amd64/go1.18.5

Public key verification OK!
```

Once the handshake is complete (verification of keys and MAC is successful) there is also a verification of public key received via `hello` message with key from enode link. They must be identical.

If there is `Public key verification OK!` at the end of log output then all checks are ok and handshake is complete


Additionally, most geth instances allow new connection for about 60 seconds. If the live test is run too often the connection will be refused:

```
Connecting to 195.201.207.37:30303
Remote public key 024a3d84a401ea8a9cce6236a6f152927cceef917fc9027f09f4ac8215f26e908c
Connected!
Error: SocketClosedByRemote
```

### Testing using public nodes

Go to `https://ethernodes.org/nodes` and sort the nodes by `Last Seen`. Try to use nodes further down the list, the ones on the top are usually to busy and will return `Too Many Peers` error:

```
Connecting to 165.22.204.22:30303
Remote public key 027c9e4cb5a7175822f1967671b2da02beaf9894a5deba7fd33e9844a48231af8f
Connected!
Received valid ack
Received disconnect message, reason: 4
Error: SocketClosedByRemote
```

Current implementation was tested against geth nodes

### Testing using local geth

Geth can be run either by downloading build executable from `https://geth.ethereum.org/downloads` or build it from sources `https://github.com/ethereum/go-ethereum`

#### Building from source

Get sources 
`git clone https://github.com/ethereum/go-ethereum.git`

Building geth requires both a Go (version 1.18 or later) and a C compiler. You can install them using your favorite package manager. 

Once the dependencies are installed, run
`make geth`

#### Running geth

If you choose option to build geth your binary is in folder `./build/bin/`.

Next run
`./build/bin/geth --datadir dev/ --nodiscover`

This will startup local node, with disabled peer discovery and custom datadir. This is not working node, it will not have information about blocks and transactions. However it is enough to test handshake.

After node startup look for the log entry similar to this:
```
INFO [01-18|11:24:50.902] Started P2P networking                   self="enode://63f760c68c2b5caf84b921b206d0e2a78e70e7a78efc8afc9054800f9b131a78d183e8214f7daa1dbf3490285395f581372500bc1b6faf35bd3c0ed31270a449@127.0.0.1:30303?discport=0"
```

This contains enode path that we will use in tests, in this example it is
```
63f760c68c2b5caf84b921b206d0e2a78e70e7a78efc8afc9054800f9b131a78d183e8214f7daa1dbf3490285395f581372500bc1b6faf35bd3c0ed31270a449@127.0.0.1:30303
```

#### Running test

Go to main folder and run
```
cargo run 63f760c68c2b5caf84b921b206d0e2a78e70e7a78efc8afc9054800f9b131a78d183e8214f7daa1dbf3490285395f581372500bc1b6faf35bd3c0ed31270a449@127.0.0.1:30303
```

Where the parameter after run is enode we got while starting geth

This will build and run handshake test with against our node.