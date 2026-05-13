"""
Flow state machine.

Each Flow instance tracks one bidirectional network flow.
Statistics are updated incrementally (O(1) per packet) using Welford's
algorithm — no packet objects are ever stored.
"""

import socket
import struct
from ._stats import RunningStats
from ._constants import (
    ACTIVE_TIMEOUT, CLUMP_TIMEOUT, BULK_BOUND,
    FORWARD, BACKWARD,
    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR,
)


class Flow:
    """Bidirectional network flow with incremental feature computation."""

    __slots__ = (
        # Identity
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        # Timestamps
        "start_time", "latest_time",
        # Packet / byte counts
        "fwd_pkt_count", "bwd_pkt_count",
        "fwd_total_bytes", "bwd_total_bytes",
        # Packet length stats (per direction + combined)
        "fwd_pkt_len", "bwd_pkt_len", "all_pkt_len",
        # Header totals
        "fwd_header_bytes", "bwd_header_bytes",
        # Forward segment size minimum (= forward IP header length)
        "fwd_seg_size_min",
        # Forward packets that carried payload
        "fwd_act_data_pkts",
        # Inter-arrival times
        "fwd_iat", "bwd_iat", "flow_iat",
        "last_fwd_time", "last_bwd_time", "last_pkt_time",
        # TCP flags
        "fwd_psh_cnt", "bwd_psh_cnt",
        "fwd_urg_cnt", "bwd_urg_cnt",
        "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt",
        "ack_cnt", "urg_cnt", "ece_cnt", "cwr_cnt",
        # TCP initial window sizes (first packet per direction)
        "init_fwd_win", "init_bwd_win",
        # Active / idle periods
        "active", "idle",
        "last_active_start", "last_activity_time",
        # Bulk transfer — forward
        "fwd_bulk_state_count",
        "fwd_bulk_size_helper", "fwd_bulk_packet_helper",
        "fwd_bulk_total_size", "fwd_bulk_total_pkts", "fwd_bulk_total_dur",
        "fwd_bulk_start", "fwd_bulk_last_ts",
        # Bulk transfer — backward
        "bwd_bulk_state_count",
        "bwd_bulk_size_helper", "bwd_bulk_packet_helper",
        "bwd_bulk_total_size", "bwd_bulk_total_pkts", "bwd_bulk_total_dur",
        "bwd_bulk_start", "bwd_bulk_last_ts",
        # Subflow tracking
        "subflow_count",
        "subflow_fwd_pkts", "subflow_fwd_bytes",
        "subflow_bwd_pkts", "subflow_bwd_bytes",
        "subflow_last_ts",
    )

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        timestamp: float,
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = timestamp
        self.latest_time = timestamp

        self.fwd_pkt_count = 0
        self.bwd_pkt_count = 0
        self.fwd_total_bytes = 0
        self.bwd_total_bytes = 0

        self.fwd_pkt_len = RunningStats()
        self.bwd_pkt_len = RunningStats()
        self.all_pkt_len = RunningStats()

        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0
        self.fwd_seg_size_min = 0xFFFF
        self.fwd_act_data_pkts = 0

        self.fwd_iat = RunningStats()
        self.bwd_iat = RunningStats()
        self.flow_iat = RunningStats()
        self.last_fwd_time = 0.0
        self.last_bwd_time = 0.0
        self.last_pkt_time = 0.0

        self.fwd_psh_cnt = 0
        self.bwd_psh_cnt = 0
        self.fwd_urg_cnt = 0
        self.bwd_urg_cnt = 0
        self.fin_cnt = 0
        self.syn_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0
        self.urg_cnt = 0
        self.ece_cnt = 0
        self.cwr_cnt = 0

        self.init_fwd_win = -1
        self.init_bwd_win = -1

        self.active = RunningStats()
        self.idle = RunningStats()
        self.last_active_start = timestamp
        self.last_activity_time = timestamp

        # Forward bulk
        self.fwd_bulk_state_count = 0
        self.fwd_bulk_size_helper = 0
        self.fwd_bulk_packet_helper = 0
        self.fwd_bulk_total_size = 0
        self.fwd_bulk_total_pkts = 0
        self.fwd_bulk_total_dur = 0.0
        self.fwd_bulk_start = 0.0
        self.fwd_bulk_last_ts = 0.0

        # Backward bulk
        self.bwd_bulk_state_count = 0
        self.bwd_bulk_size_helper = 0
        self.bwd_bulk_packet_helper = 0
        self.bwd_bulk_total_size = 0
        self.bwd_bulk_total_pkts = 0
        self.bwd_bulk_total_dur = 0.0
        self.bwd_bulk_start = 0.0
        self.bwd_bulk_last_ts = 0.0

        # Subflow
        self.subflow_count = 1
        self.subflow_fwd_pkts = 0
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_pkts = 0
        self.subflow_bwd_bytes = 0
        self.subflow_last_ts = -1.0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_packet(
        self,
        direction: int,
        pkt_len: int,
        header_len: int,
        payload_len: int,
        timestamp: float,
        flags: int = 0,
        window: int = -1,
    ) -> None:
        """Integrate one packet into the flow. All operations are O(1)."""
        self.latest_time = timestamp

        # Subflow / active-idle must run before updating last_pkt_time
        self._update_subflow(timestamp)
        self._update_active_idle(timestamp)

        # IAT
        if self.last_pkt_time > 0.0:
            self.flow_iat.update(timestamp - self.last_pkt_time)
        self.last_pkt_time = timestamp

        if direction == FORWARD:
            self.fwd_pkt_count += 1
            self.fwd_total_bytes += pkt_len
            self.fwd_pkt_len.update(pkt_len)
            self.all_pkt_len.update(pkt_len)
            self.fwd_header_bytes += header_len
            if header_len < self.fwd_seg_size_min:
                self.fwd_seg_size_min = header_len
            if payload_len > 0:
                self.fwd_act_data_pkts += 1
            if self.last_fwd_time > 0.0:
                self.fwd_iat.update(timestamp - self.last_fwd_time)
            self.last_fwd_time = timestamp
            if self.init_fwd_win == -1 and window >= 0:
                self.init_fwd_win = window
            if flags & TCP_PSH:
                self.fwd_psh_cnt += 1
            if flags & TCP_URG:
                self.fwd_urg_cnt += 1
        else:
            self.bwd_pkt_count += 1
            self.bwd_total_bytes += pkt_len
            self.bwd_pkt_len.update(pkt_len)
            self.all_pkt_len.update(pkt_len)
            self.bwd_header_bytes += header_len
            if self.last_bwd_time > 0.0:
                self.bwd_iat.update(timestamp - self.last_bwd_time)
            self.last_bwd_time = timestamp
            if self.init_bwd_win == -1 and window >= 0:
                self.init_bwd_win = window
            if flags & TCP_PSH:
                self.bwd_psh_cnt += 1
            if flags & TCP_URG:
                self.bwd_urg_cnt += 1

        # Directional-agnostic TCP flags
        if flags:
            if flags & TCP_FIN:
                self.fin_cnt += 1
            if flags & TCP_SYN:
                self.syn_cnt += 1
            if flags & TCP_RST:
                self.rst_cnt += 1
            if flags & TCP_PSH:
                self.psh_cnt += 1
            if flags & TCP_ACK:
                self.ack_cnt += 1
            if flags & TCP_URG:
                self.urg_cnt += 1
            if flags & TCP_ECE:
                self.ece_cnt += 1
            if flags & TCP_CWR:
                self.cwr_cnt += 1

        self._update_bulk(direction, payload_len, timestamp)

    def to_dict(self) -> dict:
        """Return all 81 flow features as an ordered flat dict."""
        duration = self.latest_time - self.start_time
        total_pkts = self.fwd_pkt_count + self.bwd_pkt_count
        total_bytes = self.fwd_total_bytes + self.bwd_total_bytes

        flow_byts_s = total_bytes / duration if duration > 0 else 0.0
        flow_pkts_s = total_pkts / duration if duration > 0 else 0.0
        fwd_pkts_s = self.fwd_pkt_count / duration if duration > 0 else 0.0
        bwd_pkts_s = self.bwd_pkt_count / duration if duration > 0 else 0.0

        down_up = (
            self.bwd_pkt_count / self.fwd_pkt_count
            if self.fwd_pkt_count > 0
            else 0.0
        )
        pkt_size_avg = (
            total_bytes / total_pkts if total_pkts > 0 else 0.0
        )

        fwd_seg_avg = (
            self.fwd_total_bytes / self.fwd_pkt_count
            if self.fwd_pkt_count > 0
            else 0.0
        )
        bwd_seg_avg = (
            self.bwd_total_bytes / self.bwd_pkt_count
            if self.bwd_pkt_count > 0
            else 0.0
        )

        sf_count = max(self.subflow_count, 1)

        # Bulk averages
        fwd_byts_b_avg = (
            self.fwd_bulk_total_size / self.fwd_bulk_state_count
            if self.fwd_bulk_state_count > 0
            else 0.0
        )
        fwd_pkts_b_avg = (
            self.fwd_bulk_total_pkts / self.fwd_bulk_state_count
            if self.fwd_bulk_state_count > 0
            else 0.0
        )
        fwd_blk_rate_avg = (
            self.fwd_bulk_total_size / self.fwd_bulk_total_dur
            if self.fwd_bulk_total_dur > 0
            else 0.0
        )
        bwd_byts_b_avg = (
            self.bwd_bulk_total_size / self.bwd_bulk_state_count
            if self.bwd_bulk_state_count > 0
            else 0.0
        )
        bwd_pkts_b_avg = (
            self.bwd_bulk_total_pkts / self.bwd_bulk_state_count
            if self.bwd_bulk_state_count > 0
            else 0.0
        )
        bwd_blk_rate_avg = (
            self.bwd_bulk_total_size / self.bwd_bulk_total_dur
            if self.bwd_bulk_total_dur > 0
            else 0.0
        )

        fwd_seg_min = (
            self.fwd_seg_size_min if self.fwd_seg_size_min < 0xFFFF else 0
        )

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": self.start_time,
            "flow_duration": duration,
            "flow_byts_s": flow_byts_s,
            "flow_pkts_s": flow_pkts_s,
            "fwd_pkts_s": fwd_pkts_s,
            "bwd_pkts_s": bwd_pkts_s,
            "tot_fwd_pkts": self.fwd_pkt_count,
            "tot_bwd_pkts": self.bwd_pkt_count,
            "totlen_fwd_pkts": self.fwd_total_bytes,
            "totlen_bwd_pkts": self.bwd_total_bytes,
            "fwd_pkt_len_max": self.fwd_pkt_len.safe_max,
            "fwd_pkt_len_min": self.fwd_pkt_len.safe_min,
            "fwd_pkt_len_mean": self.fwd_pkt_len.mean,
            "fwd_pkt_len_std": self.fwd_pkt_len.std,
            "bwd_pkt_len_max": self.bwd_pkt_len.safe_max,
            "bwd_pkt_len_min": self.bwd_pkt_len.safe_min,
            "bwd_pkt_len_mean": self.bwd_pkt_len.mean,
            "bwd_pkt_len_std": self.bwd_pkt_len.std,
            "pkt_len_max": self.all_pkt_len.safe_max,
            "pkt_len_min": self.all_pkt_len.safe_min,
            "pkt_len_mean": self.all_pkt_len.mean,
            "pkt_len_std": self.all_pkt_len.std,
            "pkt_len_var": self.all_pkt_len.variance,
            "fwd_header_len": self.fwd_header_bytes,
            "bwd_header_len": self.bwd_header_bytes,
            "fwd_seg_size_min": fwd_seg_min,
            "fwd_act_data_pkts": self.fwd_act_data_pkts,
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_max": self.flow_iat.safe_max,
            "flow_iat_min": self.flow_iat.safe_min,
            "flow_iat_std": self.flow_iat.std,
            "fwd_iat_tot": self.fwd_iat.total,
            "fwd_iat_max": self.fwd_iat.safe_max,
            "fwd_iat_min": self.fwd_iat.safe_min,
            "fwd_iat_mean": self.fwd_iat.mean,
            "fwd_iat_std": self.fwd_iat.std,
            "bwd_iat_tot": self.bwd_iat.total,
            "bwd_iat_max": self.bwd_iat.safe_max,
            "bwd_iat_min": self.bwd_iat.safe_min,
            "bwd_iat_mean": self.bwd_iat.mean,
            "bwd_iat_std": self.bwd_iat.std,
            "fwd_psh_flags": self.fwd_psh_cnt,
            "bwd_psh_flags": self.bwd_psh_cnt,
            "fwd_urg_flags": self.fwd_urg_cnt,
            "bwd_urg_flags": self.bwd_urg_cnt,
            "fin_flag_cnt": self.fin_cnt,
            "syn_flag_cnt": self.syn_cnt,
            "rst_flag_cnt": self.rst_cnt,
            "psh_flag_cnt": self.psh_cnt,
            "ack_flag_cnt": self.ack_cnt,
            "urg_flag_cnt": self.urg_cnt,
            "ece_flag_cnt": self.ece_cnt,
            "down_up_ratio": down_up,
            "pkt_size_avg": pkt_size_avg,
            "fwd_seg_size_avg": fwd_seg_avg,
            "bwd_seg_size_avg": bwd_seg_avg,
            "fwd_byts_b_avg": fwd_byts_b_avg,
            "fwd_pkts_b_avg": fwd_pkts_b_avg,
            "fwd_blk_rate_avg": fwd_blk_rate_avg,
            "bwd_byts_b_avg": bwd_byts_b_avg,
            "bwd_pkts_b_avg": bwd_pkts_b_avg,
            "bwd_blk_rate_avg": bwd_blk_rate_avg,
            "subflow_fwd_pkts": self.fwd_pkt_count // sf_count,
            "subflow_fwd_byts": self.fwd_total_bytes // sf_count,
            "subflow_bwd_pkts": self.bwd_pkt_count // sf_count,
            "subflow_bwd_byts": self.bwd_total_bytes // sf_count,
            "init_fwd_win_byts": self.init_fwd_win,
            "init_bwd_win_byts": self.init_bwd_win,
            "active_max": self.active.safe_max,
            "active_min": self.active.safe_min,
            "active_mean": self.active.mean,
            "active_std": self.active.std,
            "idle_max": self.idle.safe_max,
            "idle_min": self.idle.safe_min,
            "idle_mean": self.idle.mean,
            "idle_std": self.idle.std,
            "cwr_flag_count": self.cwr_cnt,
        }

    # ------------------------------------------------------------------
    # Internal helpers — all O(1)
    # ------------------------------------------------------------------

    def _update_active_idle(self, timestamp: float) -> None:
        if self.last_activity_time == 0.0:
            self.last_activity_time = timestamp
            self.last_active_start = timestamp
            return

        gap = timestamp - self.last_activity_time
        if gap > ACTIVE_TIMEOUT:
            # Close out the active period, open an idle period
            active_dur = self.last_activity_time - self.last_active_start
            if active_dur > 0:
                self.active.update(active_dur)
            self.idle.update(gap)
            self.last_active_start = timestamp

        self.last_activity_time = timestamp

    def _update_subflow(self, timestamp: float) -> None:
        if self.subflow_last_ts < 0.0:
            self.subflow_last_ts = timestamp
            return
        if (timestamp - self.subflow_last_ts) > CLUMP_TIMEOUT:
            self.subflow_count += 1
        self.subflow_last_ts = timestamp

    def _update_bulk(
        self, direction: int, payload_len: int, timestamp: float
    ) -> None:
        """Replicate CICFlowMeter's bulk-detection logic, O(1)."""
        if direction == FORWARD:
            if payload_len == 0:
                # Payload-less packet resets the helper window
                if self.fwd_bulk_packet_helper > BULK_BOUND:
                    self.fwd_bulk_state_count += 1
                    dur = self.fwd_bulk_last_ts - self.fwd_bulk_start
                    self.fwd_bulk_total_size += self.fwd_bulk_size_helper
                    self.fwd_bulk_total_pkts += self.fwd_bulk_packet_helper
                    self.fwd_bulk_total_dur += dur
                self.fwd_bulk_size_helper = 0
                self.fwd_bulk_packet_helper = 0
                self.fwd_bulk_start = 0.0
            else:
                if self.fwd_bulk_start == 0.0:
                    self.fwd_bulk_start = timestamp
                self.fwd_bulk_packet_helper += 1
                self.fwd_bulk_size_helper += payload_len
                self.fwd_bulk_last_ts = timestamp
        else:
            if payload_len == 0:
                if self.bwd_bulk_packet_helper > BULK_BOUND:
                    self.bwd_bulk_state_count += 1
                    dur = self.bwd_bulk_last_ts - self.bwd_bulk_start
                    self.bwd_bulk_total_size += self.bwd_bulk_size_helper
                    self.bwd_bulk_total_pkts += self.bwd_bulk_packet_helper
                    self.bwd_bulk_total_dur += dur
                self.bwd_bulk_size_helper = 0
                self.bwd_bulk_packet_helper = 0
                self.bwd_bulk_start = 0.0
            else:
                if self.bwd_bulk_start == 0.0:
                    self.bwd_bulk_start = timestamp
                self.bwd_bulk_packet_helper += 1
                self.bwd_bulk_size_helper += payload_len
                self.bwd_bulk_last_ts = timestamp
