# Reject named pipes for OTLP header files

Opening a read-only named pipe blocks until a writer connects. Reading an OTLP
header file during startup could therefore hang forever when the configured
path named a FIFO, before the code had a chance to reject it as non-regular.

On Unix, the reader now opens with `O_NONBLOCK`, then checks and reads the
metadata from that same handle. This preserves the check-then-read protection
against path replacement while allowing FIFOs and other non-regular files to
be rejected immediately. The startup integration test creates a FIFO with no
writer and confirms the command exits promptly.
