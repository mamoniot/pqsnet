# TODO

## Transport
### Core
- Send handshake messages
- Add session-level approval or rejection of offline key
- Allow for dynamic length payloads
- Handshake resends
- Resumption API
- Socket coherency after resumption
- Handshake and socket expiration
### Extraneous
- Structure init_table as a cache with strict upper limits
- Come up with a better name
- Update protocol full name with new name
- Zeroize stack
- Input sanitize mtu
- Improve desegmentation API
- Improve key bundle timestamp handling
- API for determining maximum allowable payload length
- Implement Debug for all public types
- Add improved timestamp checking API for key bundles

## Session
### Core
- Negotiate limits on the number of channels that can be opened before the next sync, so that the send limits and recv limits may never be exceeded.
- Add TTL options for channels and sessions
### Extraneous
