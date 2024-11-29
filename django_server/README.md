# Shallot List Server
This is a basic Django http server that manages the list of nodes connected to a Shallot network.

## Important Setup
Copy `default.env` to `.env` and **change the default settings**. Note that the server currently does not accept
requests coming from `localhost`.

## API Documentation
```
POST /api/register
```
Required fields:
- name: string (unique)
- port: number
- pubkey: string (base64)

(Note: ip address is automatically inferred)

Response: OK if successful, HTTP 400 if request is invalid.

```
GET /api/list
```
No fields.

Response: JSON dict of currently registered nodes on list server.

Example response:
```
{
    "Alice": {
        "ip": "127.0.0.1",
        "port": 53600,
        "pubkey": "PubKeyInBase64=="
    }
}
```

Note that nodes are considered stale and removed after 60 seconds by default.
