from trex_stl_lib.api import *

LOGICAL_PKT_SIZE = 64

DUT_MAC = "3c:fd:fe:b3:12:9c"
DST_IP = "10.10.1.1"


class STLS1(object):

    def build_logical_packet(self, src_ip, sport, dport, marker):

        pkt = (
            Ether(dst=DUT_MAC) /
            IP(src=src_ip, dst=DST_IP) /
            UDP(
                sport=sport,
                dport=dport,
                chksum=0
            )
        )

        payload_len = LOGICAL_PKT_SIZE - len(pkt)

        if payload_len < 0:
            raise RuntimeError("Packet headers exceed 64 bytes")

        pkt = pkt / Raw(bytes([marker]) * payload_len)

        raw = bytes(pkt)

        assert len(raw) == LOGICAL_PKT_SIZE

        return raw


    def get_streams(self, direction=0, **kwargs):

        pkt0 = self.build_logical_packet(
            src_ip="10.10.1.10",
            sport=10000,
            dport=12000,
            marker=0x40
        )

        pkt1 = self.build_logical_packet(
            src_ip="10.10.1.11",
            sport=10001,
            dport=12001,
            marker=0x41
        )

        pkt2 = self.build_logical_packet(
            src_ip="10.10.1.12",
            sport=10002,
            dport=12002,
            marker=0x42
        )

        pkt3 = self.build_logical_packet(
            src_ip="10.10.1.13",
            sport=10003,
            dport=12003,
            marker=0x43
        )

        batch_raw = pkt0 + pkt1 + pkt2 + pkt3

        assert len(batch_raw) == 256

        #
        # TRex sees this as ONE physical Ethernet frame.
        #
        batch_pkt = Ether(batch_raw)

        assert len(bytes(batch_pkt)) == 256

        return [
            STLStream(
                packet=STLPktBuilder(
                    pkt=batch_pkt
                ),

                mode=STLTXSingleBurst(
    total_pkts=1,
    pps=1
)
            )
        ]


def register():
    return STLS1()
