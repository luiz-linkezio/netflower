"""
FlowSession: maintains the table of active flows, routes packets to the
correct Flow object, and evicts expired flows to the writer.
"""

from ._flow import Flow
from ._constants import FLOW_TIMEOUT, FORWARD, BACKWARD, TCP_FIN, TCP_RST


class FlowSession:
    """
    Tracks bidirectional TCP/UDP flows from a stream of parsed packets.

    Flow key: (proto, src_ip, dst_ip, src_port, dst_port) where src/dst
    are fixed at flow-creation time (first packet direction is FORWARD).

    flow_timeout is the idle timeout: seconds of inactivity before a flow
    is flushed. active_timeout, when set, additionally caps the absolute
    flow duration regardless of activity.
    """

    def __init__(
        self,
        writer,
        flow_timeout: float = FLOW_TIMEOUT,
        active_timeout: float | None = None,
    ) -> None:
        self._flows: dict[tuple, Flow] = {}
        self._writer = writer
        self._timeout = flow_timeout
        self._active_timeout = active_timeout

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
            flow = self._flows[fwd_key]
            direction = FORWARD
        elif bwd_key in self._flows:
            flow = self._flows[bwd_key]
            direction = BACKWARD
        else:
            # New flow — this packet is the FORWARD initiator
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
            self._flows[fwd_key] = flow
            direction = FORWARD

        # Expire flows that idled too long or exceeded the absolute duration
        # cap (treat the current packet as the start of a new flow)
        if self._expired(flow, timestamp):
            self._flush_flow(fwd_key if direction == FORWARD else bwd_key, flow)
            flow = Flow(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
            self._flows[fwd_key] = flow
            direction = FORWARD

        flow.add_packet(direction, pkt_len, header_len, payload_len, timestamp, flags, window)

        # Early eviction: RST aborts the connection immediately; FIN closes
        # it only once both directions have sent one (CICFlowMeter semantics)
        if flags & TCP_RST or (
            flags & TCP_FIN and flow.fwd_fin_cnt > 0 and flow.bwd_fin_cnt > 0
        ):
            key = fwd_key if direction == FORWARD else bwd_key
            self._flush_flow(key, flow)

    def gc(self, current_time: float) -> None:
        """Evict flows that exceeded the idle timeout or the duration cap."""
        expired = [
            key
            for key, flow in self._flows.items()
            if (current_time - flow.latest_time) >= self._timeout
            or self._past_duration_cap(flow, current_time)
        ]
        for key in expired:
            self._flush_flow(key, self._flows[key])

    def _expired(self, flow: Flow, timestamp: float) -> bool:
        idle = flow.latest_time > 0 and (timestamp - flow.latest_time) > self._timeout
        return idle or self._past_duration_cap(flow, timestamp)

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
