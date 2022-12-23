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

If everything is ok peer node can print something like this:
```
2022-12-23T20:42:01.493921379Z TRACE[12-23|20:42:01.493] Accepted connection                      addr=172.18.0.1:55316
2022-12-23T20:42:01.507133169Z DEBUG[12-23|20:42:01.505] Adding p2p peer                          peercount=1 id=b4916e3bb904a657 conn=inbound addr=172.18.0.1:55316 name="p2p handshaker 0.1.0"
2022-12-23T20:42:01.507864695Z INFO [12-23|20:42:01.507] Looking for peers                        peercount=1 tried=0 static=0
2022-12-23T20:42:01.508618582Z TRACE[12-23|20:42:01.507] Starting protocol eth/66                 id=b4916e3bb904a657 conn=inbound
2022-12-23T20:42:06.511247338Z DEBUG[12-23|20:42:06.507] Ethereum handshake failed                id=b4916e3bb904a657 conn=inbound err=EOF
2022-12-23T20:42:06.512289953Z DEBUG[12-23|20:42:06.511] Removing p2p peer                        peercount=0 id=b4916e3bb904a657 duration=5.006s req=false err="snappy: corrupt input"
```
Ethereum handshake failure is expected as its a higher level protocol and expects snappy compression capability to be enabled. However our little demo sticks to p2p rlpx only.