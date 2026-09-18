from trex_stl_lib.api import *

NUM_FLOWS = 100_000

LOGICAL_PKT_SIZE = 64
BATCH_SIZE = 4
BATCH_FRAME_SIZE = LOGICAL_PKT_SIZE * BATCH_SIZE   # 256 bytes

SRC_IP = "10.10.1.2"
DST_IP = "10.10.1.1"

# node0 experiment-interface MAC
DUT_MAC = "3c:fd:fe:b3:12:9c"


class STLS1(object):

    def build_logical_packet(self, sport, dport, marker):

        pkt = (
            Ether(dst=DUT_MAC) /
            IP(src=SRC_IP, dst=DST_IP) /
            UDP(
                sport=sport,
                dport=dport,
                chksum=0
            )
        )

        payload_len = LOGICAL_PKT_SIZE - len(pkt)

        if payload_len < 0:
            raise RuntimeError("Headers exceed logical packet size")

        pkt = pkt / Raw(bytes([marker]) * payload_len)

        raw = bytes(pkt)

        assert len(raw) == LOGICAL_PKT_SIZE, \
            "logical packet is %d bytes instead of %d" % (
                len(raw), LOGICAL_PKT_SIZE
            )

        return raw


    def build_batch(self, dport_base):

        pkts = []

        for i in range(BATCH_SIZE):
            pkt = self.build_logical_packet(
                sport=1025 + i,
                dport=dport_base + i,
                marker=0x40 + i
            )

            pkts.append(pkt)

        batch_raw = b''.join(pkts)

        assert len(batch_raw) == BATCH_FRAME_SIZE
        assert len(batch_raw) == 256

        #
        # Parse the complete 256-byte byte string as ONE
        # Ethernet frame for TRex.
        #
        batch_pkt = Ether(batch_raw)

        assert len(bytes(batch_pkt)) == 256

        return batch_pkt


    def create_stream(self, dport_base, logical_flows):

        #
        # Four independent logical flow ranges.
        #
        # Example:
        #
        # logical_flows = 50000
        # flows_per_lane = 12500
        #
        # lane 0 -> 12500 flows
        # lane 1 -> 12500 flows
        # lane 2 -> 12500 flows
        # lane 3 -> 12500 flows
        #
        # Total = 50000 logical flows per stream.
        #
        flows_per_lane = logical_flows // BATCH_SIZE

        if logical_flows % BATCH_SIZE != 0:
            raise RuntimeError(
                "logical_flows must be divisible by 4"
            )

        pkt = self.build_batch(dport_base)

        vm_cmds = []

        for i in range(BATCH_SIZE):

            name = "sport%d" % i

            min_sport = 1025 + i * flows_per_lane
            max_sport = min_sport + flows_per_lane - 1

            #
            # UDP.sport inside logical packet i:
            #
            # i * 64 + Ethernet(14) + IPv4(20)
            #
            sport_offset = (
                i * LOGICAL_PKT_SIZE +
                14 +
                20
            )

            vm_cmds.append(
                STLVmFlowVar(
                    name=name,
                    min_value=min_sport,
                    max_value=max_sport,
                    size=2,
                    op="inc"
                )
            )

            vm_cmds.append(
                STLVmWrFlowVar(
                    fv_name=name,
                    pkt_offset=sport_offset
                )
            )

        vm = STLScVmRaw(vm_cmds)

        return STLStream(
            packet=STLPktBuilder(
                pkt=pkt,
                vm=vm
            ),

            mode=STLTXCont(
                percentage=50
            )
        )


    def get_streams(self, direction=0, **kwargs):

        #
        # 50k logical flows per stream.
        #
        # 2 streams = 100k logical flows total.
        #
        return [
            self.create_stream(
                dport_base=12000,
                logical_flows=NUM_FLOWS // 2
            ),

            self.create_stream(
                dport_base=12100,
                logical_flows=NUM_FLOWS // 2
            )
        ]


def register():
    return STLS1()
