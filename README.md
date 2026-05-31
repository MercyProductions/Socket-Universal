# Socket-Universal

SocketUniversal is a Windows DLL for local network debugging and traffic inspection.

## Current coverage

- Winsock socket lifecycle, DNS, send/receive, overlapped completions, and extension functions.
- WinHTTP and WinINet request, response, header, read, and write APIs.
- SChannel plus dynamically loaded OpenSSL/BoringSSL `SSL_read` and `SSL_write` style APIs.
- Console output, text log, JSONL log, named-pipe stream, redaction, payload previews, chunked preview decoding, and log rotation.

## Runtime switches

Set these environment variables before loading the DLL:

- `SOCKETUNIVERSAL_MAX_DUMP_BYTES=0` disables payload preview truncation.
- `SOCKETUNIVERSAL_REDACT=0` disables credential redaction.
- `SOCKETUNIVERSAL_CONSOLE=0` disables console allocation/output.
- `SOCKETUNIVERSAL_DUMP_DATA=0` disables payload previews.
- `SOCKETUNIVERSAL_LOG_FILE=path` changes the text log path.
- `SOCKETUNIVERSAL_JSONL_FILE=path` changes the JSONL log path.
- `SOCKETUNIVERSAL_PIPE=0` disables the named-pipe stream.
- `SOCKETUNIVERSAL_PIPE_NAME=\\.\pipe\SocketUniversal` changes the pipe name.
- `SOCKETUNIVERSAL_ROTATE_BYTES=10485760` changes log rotation size.
- `SOCKETUNIVERSAL_ROTATE_FILES=5` changes rotated log retention.

Redaction is enabled by default.
