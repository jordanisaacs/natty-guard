# `natty-guard`


A (wip) NAT Traversal and wireguard endpoint discovery for linux kernel wireguard.

## Design

Combines the STUN/ICE server with the side channel.

### Messages

#### Initialize Request (peer->server)

Server responds to Peer A with update requests for all other peer addresses.

Server sends Peer A's address to all other connected peers if it was updated/a new peer.

#### Keep-Alive request (peer->server)

Each peer sends a keep-alive message every 15 seconds to the server. If the reflexive ipaddr has changed then the server sends an update request to all other peers.

Keep-alive is necessary to keep a hole punched connection open allowing the server to send messages to the peer.

Server responds with an ack.

#### Update request (server->peer)

When a peer recieves an update request from the server it updates the wireguard configuration.

### Server Store

The server stores KV pairs. The key is the wireguard public key. The value contains:

1. IpAddr
2. Port
3. Last Response

If last response > 10 minutes, remove it

## References

https://tailscale.com/blog/how-tailscale-works/

https://tailscale.com/blog/how-nat-traversal-works/

https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/

https://git.zx2c4.com/wireguard-tools/tree/contrib/nat-hole-punching

https://resources.infosecinstitute.com/topic/udp-hole-punching/

https://bford.info/pub/net/p2pnat/

https://en.wikipedia.org/wiki/UDP_hole_punching

STUN RFC: https://datatracker.ietf.org/doc/html/rfc8489

ICE RFC: https://datatracker.ietf.org/doc/html/rfc8445
