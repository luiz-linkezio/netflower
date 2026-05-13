FLOW_TIMEOUT = 120.0    # seconds of inactivity before a flow is flushed
ACTIVE_TIMEOUT = 5.0    # gap > this separates active from idle periods
CLUMP_TIMEOUT = 1.0     # gap > this starts a new subflow
BULK_BOUND = 4          # minimum packets required to register a bulk transfer
CSV_BUFFER_ROWS = 500   # rows buffered in memory before writing to disk

# TCP flag bitmasks (RFC 793 / RFC 3168)
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

FORWARD = 0
BACKWARD = 1
