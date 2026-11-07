import os
import struct
import tempfile

from pcaplens import analyze, synth


class TmpCase:
    """Mixin giving each test a temporary directory."""

    def make_tmp(self, test):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        return tmp.name


def analysis_of(builder, directory, fmt="pcap", name="t"):
    path = os.path.join(directory, name + "." + fmt)
    (builder.write_pcapng if fmt == "pcapng" else builder.write_pcap)(path)
    return analyze.analyze_file(path)


def write_with_linktype(builder, path, linktype):
    """Re-wrap Ethernet frames of the builder using another link-layer header."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, frame in sorted(builder.records, key=lambda r: r[0]):
            ip = frame[14:]
            if linktype == 113:
                data = struct.pack(">HHH8sH", 0, 1, 6, b"\x02" * 8, 0x0800) + ip
            elif linktype == 0:
                data = struct.pack("<I", 2) + ip
            else:  # raw IP
                data = ip
            fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)) + data)


def simple_exchange(builder=None, **kw):
    b = builder or synth.Builder()
    synth.http_get(b, **kw)
    return b
