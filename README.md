## Ethereum P2P RPLX protocol handshaker

Connects to any ethereum p2p compatible node and initiates session according to spec:
- Handshakes shared secrets (public and private ephemeral keys)
- Exchanges Hello messages with capabilities

### Running (and testing)
To run handshaker:
```
Usage: eth-hand-shaker-rs --node <NODE>

Options:
--node <NODE>  URL of eth node
-h, --help         Print help information
```

The problem is that all public boot nodes are not reachable on port 30303 for unknown reasons.
In order for acceptance testing, local private node can be started by using docker compose:
- run `init` service (only once) to generate initial blockchain state from genesis
- run `geth` service to start node, listening on 30303. Node URL can be found in logs similar to:
`enode://1ef032fe92c2010668fda1d3a0ae4b8037cb47c938e8db5c817bf4eb6c8b4fcdca126b4d9bf7b3919c82f4328ed77bcf638a7b37a08ba986e1d2ffed22a71753@127.0.0.1:30303?discport=0`

Only direct eth dependency is ethereum RLP crate.