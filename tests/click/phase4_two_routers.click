// Phase 4 live two-router test (NOT an experiment). Loopback only.
//
// Asymmetric routing: the client's requests (and the flood) cross R1 only;
// the server's replies cross R2 only. Each router is monitored twice:
//   R1, R2  V1 PARTITION  -> proposal aggregator   (ROUTER_ID 1, 2)
//   R3, R4  V1 ALL        -> paper aggregator      (ROUTER_ID 3, 4; same packets as R1, R2)
// THRESH 50: R1 expands the 100 pps client to /32, R2 keeps the 30 pps replies at /8.

define($PORT 49555);

R1 :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 1, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 1, BOOT_ID 11);
R2 :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 1, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 2, BOOT_ID 12);
R3 :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 1, EXPORT ALL,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 3, BOOT_ID 13);
R4 :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 1, EXPORT ALL,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 4, BOOT_ID 14);

req :: Null;
rep :: Null;
RatedSource(LENGTH 22, RATE 2000) -> UDPIPEncap(10.0.0.1, 5000, 18.0.0.1, 80)
  -> MarkIPHeader -> cA :: Counter -> req;
RatedSource(LENGTH 22, RATE 100) -> UDPIPEncap(192.168.1.1, 4000, 192.168.1.2, 53)
  -> MarkIPHeader -> cH :: Counter -> req;
RatedSource(LENGTH 22, RATE 30) -> UDPIPEncap(192.168.1.2, 53, 192.168.1.1, 4000)
  -> MarkIPHeader -> cR :: Counter -> rep;

req -> [0]R1[0] -> [0]R3[0] -> Discard;
Idle -> [0]R2[0] -> Discard;
Idle -> [0]R4[0] -> Discard;
rep -> [1]R2[1] -> [1]R4[1] -> Discard;

DriverManager(
  wait 8s,
  print "=== counts", print cA.count, print cH.count, print cR.count,
  write R1.export, write R2.export, write R3.export, write R4.export,
  print "=== end",
  stop);
