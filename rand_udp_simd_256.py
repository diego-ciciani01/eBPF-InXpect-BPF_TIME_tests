
from trex_stl_lib.api import *

NUM_FLOWS = 100_000
FRAME_SIZE = 256

SRC_IP = "10.10.1.2"   # node1 experiment interface
DST_IP = "10.10.1.1"   # node0 experiment interface

DUT_MAC = "3c:fd:fe:b3:12:9c"


class STLS1(object):

    def create_stream(self, dport, flows):

        base_pkt = (
            Ether(dst=DUT_MAC) /
            IP(src=SRC_IP, dst=DST_IP) /
            UDP(sport=1025, dport=dport, chksum=0)
        )

        payload_len = FRAME_SIZE - len(base_pkt)

        pkt = base_pkt / Raw(b'\x42' * payload_len)

        vm = STLScVmRaw([
            STLVmFlowVar(
                name="sport",
                min_value=1025,
                max_value=1025 + flows - 1,
                size=2,
                op="inc"
            ),

            STLVmWrFlowVar(
                fv_name="sport",
                pkt_offset="UDP.sport"
            ),

            STLVmFixIpv4(offset="IP")
        ])

        return STLStream(
            packet=STLPktBuilder(
                pkt=pkt,
                vm=vm
            ),

            # Each stream uses half of the link.
            # Two streams together = 100%.
            mode=STLTXCont(percentage=50)
        )


    def get_streams(self, direction=0, **kwargs):

        return [
            self.create_stream(
                dport=12000,
                flows=NUM_FLOWS // 2
            ),

            self.create_stream(
                dport=12001,
                flows=NUM_FLOWS // 2
            )
        ]


def register():
    return STLS1()
