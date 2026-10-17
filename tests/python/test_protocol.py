"""Codec tests: layout, hand-written bytes, cross-language golden vectors, fuzzing."""

import json
import os
import random
import subprocess
import unittest
from pathlib import Path

from aggregator.telemetry_protocol import (EXPORT_MODES, DecodeError, HeaderV1, PaperRecord, RecordV1,
                                           decode_paper, decode_v1, encode_paper, encode_v1,
                                           max_records_paper, max_records_v1)

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "tests" / "data" / "telemetry_vectors.jsonl"

# Same hand-written bytes as tests/cpp/test_telemetry.cpp (kGoldenHeader/kGoldenRecord).
GOLDEN_HEX = (
    "4D54014820010000" "01020304A1B2C3D4" "0000000000000005" "0000000700000001"
    "0011223344556677" "000003E800010000" "0000000000000000" "0000000000000002"
    "0000000000000003"
    "0A00000120010000" "0000270E00000000" "000000000000C3AA" "0000000000000000"
)


def golden_objects():
    h = HeaderV1("PARTITION", 0, 0x01020304, 0xA1B2C3D4, 5, 7, 0, 1, 0x0011223344556677, 1000, 1, 0, 2, 3)
    r = RecordV1("10.0.0.1", 32, 1, 9998, 0, 50090, 0)
    return h, r


class LayoutTests(unittest.TestCase):
    def test_capacity(self):
        self.assertEqual(max_records_v1(1472), 43)
        self.assertEqual(max_records_paper(1472), 91)

    def test_encode_matches_hand_written_bytes(self):
        h, r = golden_objects()
        self.assertEqual(encode_v1(h, [r]).hex().upper(), GOLDEN_HEX)

    def test_decode_hand_written_bytes(self):
        dg = decode_v1(bytes.fromhex(GOLDEN_HEX))
        h, r = golden_objects()
        self.assertEqual(dg.header, h)
        self.assertEqual(dg.records, [r])
        self.assertEqual(dg.records[0].to_rate, 9998)      # paper alias of fwd_rate
        self.assertEqual(dg.records[0].from_rate, 0)

    def test_paper_layout(self):
        data = encode_paper([PaperRecord("192.168.1.1", 32, 100, 30)])
        self.assertEqual(data.hex().upper(), "000000000001" "C0A8010120000000" "000000640000001E")
        auth, recs = decode_paper(data)
        self.assertEqual((auth, recs), (0, [PaperRecord("192.168.1.1", 32, 100, 30)]))


class GoldenVectorTests(unittest.TestCase):
    """Every vector was produced and decoded by the C++ code (tools/telemetry_vectors)."""

    @classmethod
    def setUpClass(cls):
        cls.vectors = [json.loads(line) for line in VECTORS.read_text().splitlines()]

    def test_vector_file_is_current(self):
        build = os.environ.get("MULTOPS_BUILD_DIR")
        tool = Path(build) / "telemetry_vectors" if build else None
        if not tool or not tool.exists():
            self.skipTest("MULTOPS_BUILD_DIR/telemetry_vectors not available")
        out = subprocess.run([str(tool)], check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, VECTORS.read_text())

    def test_python_agrees_with_cpp_on_every_vector(self):
        self.assertGreaterEqual(len(self.vectors), 30)
        for v in self.vectors:
            with self.subTest(v["name"]):
                data = bytes.fromhex(v["hex"])
                if v["format"] == "V1":
                    if v["error"] != "none":
                        with self.assertRaises(DecodeError) as cm:
                            decode_v1(data)
                        self.assertEqual(cm.exception.code, v["error"])
                        continue
                    dg = decode_v1(data)
                    self.assertEqual(dg.header.__dict__, v["header"])
                    self.assertEqual([r.__dict__ for r in dg.records], v["records"])
                    self.assertEqual(encode_v1(dg.header, dg.records), data)   # byte-exact
                else:
                    if v["error"] != "none":
                        with self.assertRaises(DecodeError) as cm:
                            decode_paper(data)
                        self.assertEqual(cm.exception.code, v["error"])
                        continue
                    auth, recs = decode_paper(data)
                    self.assertEqual(auth, v["auth_placeholder"])
                    self.assertEqual([r.__dict__ for r in recs], v["records"])
                    self.assertEqual(encode_paper(recs, auth), data)

    def test_every_error_code_is_covered(self):
        codes = {v["error"] for v in self.vectors}
        for c in ("too_short", "bad_magic", "bad_version", "bad_header_length", "bad_record_length",
                  "length_mismatch", "bad_export_mode", "bad_count_unit", "bad_fragment",
                  "reserved_not_zero", "bad_prefix_length", "host_bits_set", "bad_flags"):
            self.assertIn(c, codes)


class FuzzTests(unittest.TestCase):
    def test_random_round_trips(self):
        rng = random.Random(3)
        for _ in range(2000):
            mode = rng.choice(EXPORT_MODES)
            n = rng.randint(0, 5)
            recs = []
            for _ in range(n):
                plen = rng.choice([8, 16, 24, 32])
                prefix = rng.getrandbits(32) & (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
                if mode == "LEAVES":
                    flags = 1
                elif mode == "PARTITION":
                    flags = 1 if plen == 32 else rng.choice([1, 2])
                else:
                    flags = rng.choice([0, 1])
                recs.append(RecordV1(str(__import__("ipaddress").IPv4Address(prefix)), plen, flags,
                                     rng.getrandbits(32), rng.getrandbits(32),
                                     rng.getrandbits(64), rng.getrandbits(64)))
            fc = rng.randint(1, 0xFFFF)
            h = HeaderV1(mode, rng.randint(0, 1), rng.getrandbits(32), rng.getrandbits(32),
                         rng.getrandbits(64), rng.getrandbits(32), rng.randrange(fc), fc,
                         rng.getrandbits(64), rng.getrandbits(32), n, rng.getrandbits(32),
                         rng.getrandbits(64), rng.getrandbits(64))
            dg = decode_v1(encode_v1(h, recs))
            self.assertEqual(dg.header, h)
            self.assertEqual(dg.records, recs)

    def test_mutated_bytes_only_raise_decode_error(self):
        rng = random.Random(11)
        base = bytes.fromhex(GOLDEN_HEX)
        for _ in range(20000):
            d = bytearray(base)
            for _ in range(rng.randint(1, 4)):
                d[rng.randrange(len(d))] = rng.getrandbits(8)
            if rng.random() < 0.2:
                d = d[: rng.randrange(len(d) + 1)]
            try:
                decode_v1(bytes(d))
            except DecodeError:
                pass  # any other exception type fails the test


if __name__ == "__main__":
    unittest.main()
