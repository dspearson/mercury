# Mercury API Documentation

## WebSocket Protocol

Mercury uses a text-based protocol over WebSocket connections. All text commands use UTF-8 encoding, and binary data is sent as binary WebSocket frames.

## Connection

Connect to `ws://server:port/ws` (or `wss://` for TLS)

## Authentication

If the server requires authentication, the first message must be an AUTH command.

### Request
```
AUTH <key>
```

Where `<key>` is either:
- A simple preshared key (legacy mode)
- `client_id:password` format for multi-client authentication

### Response
- Success: `OK`
- Failure: `ERROR Invalid authentication`

After failure, the connection is closed.

## Commands

### LIST - List Available Files

Lists all `.hecate` files in the storage directory.

#### Request
```
LIST
```

#### Response
```
<filename1>
<filename2>
...
END
```

Each line contains one filename. The list ends with `END`.

### GET - Download File

Retrieves a specific file from storage.

#### Request
```
GET <filename>
```

#### Response (Success)
```
DATA
<binary chunks>
END
```

The server sends `DATA`, followed by binary WebSocket frames containing file chunks (up to 1MB each), then `END` when complete.

#### Response (Failure)
```
ERROR <reason>
```

Common errors:
- `ERROR File not found`
- `ERROR Permission denied`
- `ERROR Invalid filename`

### Upload - Store New File

Uploads a new file to the server. This is a multi-step process.

#### Step 1: Propose Filename
```
NAME <filename>
```

The filename must end with `.hecate`.

#### Response
```
ACCEPT <actual_filename>
```

The server may modify the filename to avoid collisions (e.g., adding a timestamp).

#### Step 2: Send Data
```
DATA
```

Signals the start of binary data transfer.

#### Step 3: Send Binary Chunks
Send file content as binary WebSocket frames (max 1MB per frame).

#### Step 4: Signal Completion
```
END
```

#### Final Response
```
OK <total_bytes_received>
```

### PING - Health Check

Simple connectivity check.

#### Request
```
PING
```

#### Response
```
PONG
```

## Error Handling

All errors follow the format:
```
ERROR <description>
```

Common error messages:
- `ERROR Authentication required` - Server requires auth but none provided
- `ERROR Invalid authentication` - Authentication failed
- `ERROR Invalid command` - Unknown or malformed command
- `ERROR File not found` - Requested file doesn't exist
- `ERROR Invalid filename` - Filename contains invalid characters
- `ERROR Storage error` - Server storage issue
- `ERROR File too large` - File exceeds size limit
- `ERROR No active upload` - Upload commands sent out of order

## Binary Data Format

Binary data is sent as WebSocket binary frames. Each frame contains raw file bytes with no additional framing or headers. The maximum chunk size is 1MB (1,048,576 bytes).

## Example Sessions

### Authenticated Upload
```
Client: AUTH mykey
Server: OK
Client: NAME backup.hecate
Server: ACCEPT backup.hecate
Client: DATA
Client: [binary data chunks]
Client: END
Server: OK 1048576
```

### Download with Collision
```
Client: NAME backup.hecate
Server: ACCEPT backup-20250905-123456.hecate
Client: DATA
Client: [binary data]
Client: END
Server: OK 2097152
```

### List and Download
```
Client: LIST
Server: backup1.hecate
Server: backup2.hecate
Server: END
Client: GET backup1.hecate
Server: DATA
Server: [binary chunks]
Server: END
```

## Limits and Constraints

- Maximum file size: Configurable (default 10GB)
- Maximum chunk size: 1MB
- Maximum concurrent clients: Configurable (default 100)
- Filename restrictions:
  - Must end with `.hecate`
  - No path traversal (`..`, `/`, `\`)
  - No control characters
  - Maximum length: 255 characters
- Connection timeout: 60 seconds of inactivity

## HTTP Health Endpoint

In addition to WebSocket, Mercury provides an HTTP health endpoint:

```
GET /health
```

Response (200 OK):
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "storage_path": "/var/mercury/storage",
  "file_count": 42
}
```

## Security Considerations

1. Always use TLS in production (`wss://`)
2. Authentication tokens are sent in plaintext within the WebSocket connection
3. No built-in encryption - files are stored as received (already encrypted by Hecate)
4. File permissions on storage directory should be restrictive
5. Consider rate limiting to prevent abuse
6. Monitor for failed authentication attempts

## Notes

- All commands are case-sensitive
- Text protocol uses UTF-8 encoding
- The server maintains state per connection (e.g., authentication, active upload)
- Connections are closed after errors or completion of operations
- File listing excludes non-.hecate files for security