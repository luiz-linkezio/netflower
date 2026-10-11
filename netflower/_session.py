"""
FlowSession: maintains the table of active flows, routes packets to the
correct Flow object, and evicts expired flows to the writer.
"""

from ._flow import Flow
from ._constants import (
    FLOW_TIMEOUT, TCP_CLOSE_LINGER, FORWARD, BACKWARD,
    TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK,
)

_TCP = 6


class FlowSession:
    """
    Tracks bidirectional TCP/UDP flows from a stream of parsed packets.

    Flow key: (proto, src_ip, dst_ip, src_port, dst_port) where src/dst
    are fixed at flow-creation time (first packet direction is FORWARD).

    flow_timeout is the idle timeout: seconds of inactivity before a flow
    is flushed. active_timeout, when set, additionally caps the absolute
    flow duration regardless of activity; the flow that continues a capped
    one keeps its src/dst orientation.

    close_linger is the time, in seconds, during which packets that follow
    the end of a TCP connection (RST, or FIN from both directions) on the
    same 5-tuple are treated as leftovers of that connection and ignored,
    instead of starting a new flow. A SYN without ACK always starts a new
    flow. 0 turns this off.
    """

    def __init__(
        self,
        writer,
        flow_timeout: float = FLOW_TIMEOUT,
        active_timeout: float | None = None,
        close_linger: float = TCP_CLOSE_LINGER,
    ) -> None:
        self._flows: dict[tuple, Flow] = {}
        self._writer = writer
        self._timeout = flow_timeout
        self._active_timeout = active_timeout
        self._close_linger = close_linger
        # key of a closed TCP flow -> time of the packet that closed it
        self._closed: dict[tuple, float] = {}
        # key of a flow cut by the duration cap -> time of its last packet
        self._capped: dict[tuple, float] = {}

    def key_for(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        flags: int = 0,
    ) -> tuple | None:
        """Key of the flow process() will put this packet in, or None when
        process() will ignore the packet. Changes nothing."""
        fwd_key = (protocol, src_ip, dst_ip, src_port, dst_port)
        bwd_key = (protocol, dst_ip, src_ip, dst_port, src_port)
        if fwd_key in self._flows:
            flow, key = self._flows[fwd_key], fwd_key
        elif bwd_key in self._flows:
            flow, key = self._flows[bwd_key], bwd_key
        else:
            if self._is_leftover(fwd_key, bwd_key, timestamp, flags):
                return None
            return self._continued_key(fwd_key, bwd_key, timestamp) or fwd_key
        if self._idle(flow, timestamp):
            return fwd_key
        return key

    def process(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        pkt_len: int,
        header_len: int,
        payload_len: int,
        flags: int = 0,
        window: int = -1,
    ) -> None:
        fwd_key = (protocol, src_ip, dst_ip, src_port, dst_port)
        bwd_key = (protocol, dst_ip, src_ip, dst_port, src_port)

        if fwd_key in self._flows:
            key, direction = fwd_key, FORWARD
        elif bwd_key in self._flows:
            key, direction = bwd_key, BACKWARD
        else:
            key = None

        if key is not None:
            flow = self._flows[key]
            if self._idle(flow, timestamp):
                # Idled too long: the current packet starts a new flow and
                # its sender is the FORWARD initiator
                self._flush_flow(key, flow)
                key = None
            elif self._past_duration_cap(flow, timestamp):
                # Duration cap: the current packet continues the connection
                # in a new flow with the same orientation
                self._flush_flow(key, flow)
                self._capped.pop(key, None)
                flow = self._new_flow(key, timestamp)

        if key is None:
            if self._is_leftover(fwd_key, bwd_key, timestamp, flags):
                return
            self._closed.pop(fwd_key, None)
            self._closed.pop(bwd_key, None)
            key = self._continued_key(fwd_key, bwd_key, timestamp) or fwd_key
            self._capped.pop(fwd_key, None)
            self._capped.pop(bwd_key, None)
            direction = FORWARD if key == fwd_key else BACKWARD
            flow = self._new_flow(key, timestamp)

        flow.add_packet(direction, pkt_len, header_len, payload_len, timestamp, flags, window)

        # Early eviction: RST aborts the connection immediately; FIN closes
        # it only once both directions have sent one (CICFlowMeter semantics)
        if flags & TCP_RST or (
            flags & TCP_FIN and flow.fwd_fin_cnt > 0 and flow.bwd_fin_cnt > 0
        ):
            self._flush_flow(key, flow)
            if self._close_linger > 0:
                self._closed[key] = timestamp

    def gc(self, current_time: float) -> None:
        """Evict flows that exceeded the idle timeout or the duration cap."""
        expired = [
            key
            for key, flow in self._flows.items()
            if (current_time - flow.latest_time) >= self._timeout
            or self._past_duration_cap(flow, current_time)
        ]
        for key in expired:
            flow = self._flows[key]
            if (current_time - flow.latest_time) < self._timeout:
                # Cut by the duration cap while still active: remember the
                # orientation for the flow that continues it
                self._capped[key] = flow.latest_time
            self._flush_flow(key, flow)
        self._closed = {
            key: closed_at for key, closed_at in self._closed.items()
            if (current_time - closed_at) <= self._close_linger
        }
        self._capped = {
            key: latest for key, latest in self._capped.items()
            if (current_time - latest) <= self._timeout
        }

    def _new_flow(self, key: tuple, timestamp: float) -> Flow:
        protocol, src_ip, dst_ip, src_port, dst_port = key
        flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
        self._flows[key] = flow
        return flow

    def _idle(self, flow: Flow, timestamp: float) -> bool:
        return flow.latest_time > 0 and (timestamp - flow.latest_time) > self._timeout

    def _is_leftover(self, fwd_key: tuple, bwd_key: tuple, timestamp: float, flags: int) -> bool:
        """True for a packet that trails a TCP connection closed less than
        close_linger seconds ago on this 5-tuple and does not open a new one."""
        if fwd_key[0] != _TCP or (flags & TCP_SYN and not flags & TCP_ACK):
            return False
        closed_at = self._closed.get(fwd_key)
        if closed_at is None:
            closed_at = self._closed.get(bwd_key)
        return closed_at is not None and (timestamp - closed_at) <= self._close_linger

    def _continued_key(self, fwd_key: tuple, bwd_key: tuple, timestamp: float) -> tuple | None:
        """Key of the flow the duration cap cut on this 5-tuple, when the
        packet arrives before that flow would have idled out."""
        for key in (fwd_key, bwd_key):
            latest = self._capped.get(key)
            if latest is not None and (timestamp - latest) <= self._timeout:
                return key
        return None

    def _past_duration_cap(self, flow: Flow, timestamp: float) -> bool:
        return (
            self._active_timeout is not None
            and (timestamp - flow.start_time) > self._active_timeout
        )

    def flush_all(self) -> None:
        """Flush every remaining active flow (call at end of PCAP)."""
        for key, flow in list(self._flows.items()):
            self._flush_flow(key, flow)

    def _flush_flow(self, key: tuple, flow: Flow) -> None:
        self._writer.write(flow.to_dict())
        self._flows.pop(key, None)
