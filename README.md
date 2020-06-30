# Wireguard Controller

Wireguard Utilities

## Overivew

Manage wireguard
Provide a REST API and Web UI interface for wireguard operations

## Functions

### Generate a public key

`POST /utils/public_key`

```jsonc
{"private_key": "..."}
```

### Generate a private key

`POST /utils/private_key`

```jsonc
{}
```

### Generate an Interface Configuration

`POST /interfaces`

```jsonc
{
    "private_key": "..." // (optional),
    "address": "W.X.Y.Z/Q",
    "table" : ("1234"|"auto"|"off") // (optional),
    "mtu": 1234 // (optional)
    "dns": ["DNS1","DNS2"..."DNSX"] // (optional),
}
```

### Create an interface

`POST /interfaces/{interface_name}`

```jsonc
{
    "private_key": "..." // (optional),
    "address": "W.X.Y.Z/Q",
    "table" : ("1234"|"auto"|"off") // (optional),
    "mtu": 1234 // (optional)
    "dns": ["DNS1","DNS2", ..., "DNSX"] // (optional),
}
```

### Generate a peer configuration section

`POST /peers`

```jsonc
{
    "public_key": "...",
    "endpoint": "W.X.Y.Z/Q" // (optional),
    "allowed_ips": ["IP/MASK1", "IP/MASK2", ..., "IP/MASKX"]
}
```

### Add a peer configuration to an interface configuration

`POST /interfaces/{interface}/peer`

```jsonc
{
    "public_key": "...",
    "endpoint": "W.X.Y.Z/Q" // (optional),
    "allowed_ips": ["IP/MASK1", "IP/MASK2", ..., "IP/MASKX"]
}
```

### Remove a peer configuration from an interface configuration

`DELETE /interfaces/{interface}/peer`

```jsonc
{
    "public_key": "...",
}
```

### List interfaces

`GET /interfaces`

### Get information about a specific interface

`GET /interfaces/{interface}`

### Start an interface

`GET /interfaces/{interface}/start`

### Stop an interface

`GET /interfaces/{interface}/stop`

### Restart an interface

`GET /interfaces/{interface}/restart`

### Disable an interface

`GET /interfaces/{interface}/disable`

### Enable an interface

`GET /interfaces/{interface}/enable`

### Get information for an interface

`GET /interfaces/{interface}`

### Delete an interface

`DELETE /interfaces/{interface}`


https://swagger.io/specification/

https://mrin9.github.io/RapiDoc/


## Processes

### Provision a WG interface

- [x] inputs: interface name, address/subnet, DNS server(s)(optional), MTU (optional), Pre/Post Up/Down commands (optional), routing (table/auto/off)
- [x] generate private key
- [x] generate interface config file
- [x] save interface config to WG config dir
- [x] use wg-quick to add interface

### Provision a WG peer

- [ ] inputs: remote endpoint IP, peer interface name, peer interface address/subnet, peer interface DNS server(s)(optional), MTU (optional), peer interface Pre/Post Up/Down commands (optional), peer interface routing table (optional)
- [ ] generate private key
- [ ] derive public key
- [ ] generate peer interface config file
- [ ] generate peer section for interface
- [ ] add peer section to interface
- [ ] dump peer interface config for saving

