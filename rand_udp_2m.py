from trex_stl_lib.api import *


NUM_FLOWS   = 10
TOTAL_PKTS  = 10_000_000


class STLS1(object):

    def create_stream(self):

        base_pkt = (
            Ether() /
            IP(src="16.0.0.1", dst="48.0.0.1") /
            UDP(sport=1025, dport=12)
        )

        vm = STLScVmRaw([
            STLVmTupleGen(
                name="tuple",
                ip_min="16.0.0.1",
                ip_max="16.0.255.254",
                port_min=1025,
                port_max=65000,
                limit_flows=NUM_FLOWS
            ),

            STLVmWrFlowVar(
                fv_name="tuple.ip",
                pkt_offset="IP.src"
            ),

            STLVmWrFlowVar(
                fv_name="tuple.port",
                pkt_offset="UDP.sport"
            ),

            STLVmFixIpv4(offset="IP")
        ])

        pkt = STLPktBuilder(
            pkt=base_pkt,
            vm=vm
        )

        return STLStream(
            packet=pkt,

            # Per ora continuo; il rate lo controlleremo
            # dalla console TRex.
            mode=STLTXCont()
        )

    def get_streams(self, direction=0, tunables=None, **kwargs):
        return [self.create_stream()]


def register():
    return STLS1()
