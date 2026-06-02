# Socket-Universal

SocketUniversal is a Windows DLL for local network debugging and traffic inspection.

## Current coverage

- Winsock socket lifecycle, DNS, send/receive, overlapped completions, and extension functions.
- WinHTTP and WinINet request, response, header, read, and write APIs.
- WinHTTP WebSocket upgrade, send, receive, close, shutdown, and close-status APIs.
- Raw `ws://` and `wss://` handshake detection plus WebSocket frame previews from Winsock, SChannel, OpenSSL, and upgraded HTTP handles.
- SChannel plus dynamically loaded OpenSSL/BoringSSL `SSL_read` and `SSL_write` style APIs.
- Console output, text log, JSONL log, named-pipe stream, optional redaction, payload previews, chunked preview decoding, and log rotation.
- GSC/GS2/Lua script indicators from packets, file reads, mapped script assets, call stacks, exported symbols, and module strings.

## Runtime switches

Set these environment variables before loading the DLL:

- `SOCKETUNIVERSAL_MAX_DUMP_BYTES=0` disables payload preview truncation.
- `SOCKETUNIVERSAL_REDACT=1` enables credential redaction.
- `SOCKETUNIVERSAL_CONSOLE=0` disables console allocation/output.
- `SOCKETUNIVERSAL_DUMP_DATA=0` disables payload previews.
- `SOCKETUNIVERSAL_LOG_FILE=path` changes the text log path.
- `SOCKETUNIVERSAL_JSONL_FILE=path` changes the JSONL log path.
- `SOCKETUNIVERSAL_PIPE=0` disables the named-pipe stream.
- `SOCKETUNIVERSAL_PIPE_NAME=\\.\pipe\SocketUniversal` changes the pipe name.
- `SOCKETUNIVERSAL_ROTATE_BYTES=10485760` changes log rotation size.
- `SOCKETUNIVERSAL_ROTATE_FILES=5` changes rotated log retention.
- `SOCKETUNIVERSAL_COLOR=0` disables colored console output.
- `SOCKETUNIVERSAL_CALLSTACK=0` disables return-site and call-stack capture.
- `SOCKETUNIVERSAL_CALLSTACK_FRAMES=8` changes the number of non-system call-stack frames printed.
- `SOCKETUNIVERSAL_WEBSOCKET_CAPTURE=0` disables WebSocket upgrade/message/frame logging.
- `SOCKETUNIVERSAL_WEBSOCKET_FRAME_SCAN=0` disables raw WebSocket frame parsing while keeping explicit WinHTTP WebSocket API logs.
- `SOCKETUNIVERSAL_WEBSOCKET_FRAME_LIMIT=16` caps the number of raw WebSocket frames parsed from one captured buffer.
- `SOCKETUNIVERSAL_WEBSOCKET_PREVIEW_BYTES=65536` caps the preview bytes logged per WebSocket frame.
- `SOCKETUNIVERSAL_SCRIPT_FILE_CAPTURE=0` disables `.gsc`, `.gs2`, `.csc`, `.lua`, and related script file read/map capture.
- `SOCKETUNIVERSAL_SCRIPT_EXPORT_SCAN=0` disables module export scanning for likely script VM/load/exec symbols.
- `SOCKETUNIVERSAL_SCRIPT_STRING_SCAN=0` disables module string scanning for script names and paths.
- `SOCKETUNIVERSAL_SCRIPT_EXPORT_LIMIT=256` caps per-module script export logs.
- `SOCKETUNIVERSAL_SCRIPT_STRING_LIMIT=128` caps per-module script string logs.
- `SOCKETUNIVERSAL_SCRIPT_MAP_PREVIEW_BYTES=65536` caps preview bytes for mapped script files.
- `SOCKETUNIVERSAL_GRAAL_PROBES=1` enables opt-in Graal/GS2 engine RVA probes from the known reverse-engineered offsets.
- `SOCKETUNIVERSAL_GRAAL_MODULE=MyGame.dll` selects the module that receives Graal/GS2 RVA probes.
- `SOCKETUNIVERSAL_GRAAL_DECRYPT_RVA=0x5B7454` logs decrypted GS2 bytecode buffers.
- `SOCKETUNIVERSAL_GRAAL_EXEC_RVA=0x7C3894` logs the script execution entry point.
- `SOCKETUNIVERSAL_GRAAL_BIND_RVA=0x84FFC0` logs bytecode binding to script objects.
- `SOCKETUNIVERSAL_GRAAL_EVENT_CALL_RVA=0x8132C8` logs engine event calls.
- `SOCKETUNIVERSAL_GRAAL_FIND_OBJECT_RVA=0x6614E4` logs script object lookup/create calls.
- `SOCKETUNIVERSAL_GRAAL_FIND_TABLE_RVA=0x5C2608` logs function-table lookups.
- `SOCKETUNIVERSAL_GRAAL_EXEC_EVENT_RVA=0x84C254` logs event block execution.
- `SOCKETUNIVERSAL_GRAAL_OP_CALL_RVA=0x82E11C` logs bytecode OP_Call activity.
- `SOCKETUNIVERSAL_GRAAL_LOOKUP_RVA=0x811458` logs function lookup by GraalString.
- `SOCKETUNIVERSAL_GRAAL_RESOLVE_RVA=0x826878` logs variant-to-string materialization.
- `SOCKETUNIVERSAL_GRAAL_CONTEXT_RVA=0x920630` sets the global context pointer RVA used to scan active scripts.
- `SOCKETUNIVERSAL_GRAAL_XOR_KEY_RVA=0x91DDEC` sets the 3-byte XOR key RVA used to decode script object names.

Redaction is disabled by default.
