// Phase 5 controlled detection run (NOT an experiment on real traffic). Loopback only.
// Asymmetric routing: requests and the flood cross R1 only; replies cross R2 only.
//   R1, R2  V1 PARTITION -> proposal pipeline   (ROUTER_ID 1, 2)
//   R3, R4  V1 ALL       -> paper pipeline      (ROUTER_ID 3, 4; same packets)
// Variables: $PORT, $THRESH, $ATK (flood source address).
// No mitigation: nothing in this configuration drops traffic.

define($PORT 49555, $THRESH 20, $ATK 10.0.0.1);

R1 :: CoopIPRateMonitor(PACKETS, 1, $THRESH, 0, false, INTERVAL 1, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 1, BOOT_ID 21);
R2 :: CoopIPRateMonitor(PACKETS, 1, $THRESH, 0, false, INTERVAL 1, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 2, BOOT_ID 22);
R3 :: CoopIPRateMonitor(PACKETS, 1, $THRESH, 0, false, INTERVAL 1, EXPORT ALL,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 3, BOOT_ID 23);
R4 :: CoopIPRateMonitor(PACKETS, 1, $THRESH, 0, false, INTERVAL 1, EXPORT ALL,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 4, BOOT_ID 24);

req :: Null;
rep :: Null;
RatedSource(LENGTH 22, RATE 2000) -> UDPIPEncap($ATK, 5000, 18.0.0.1, 80)
  -> MarkIPHeader -> cA :: Counter -> req;
RatedSource(LENGTH 22, RATE 100) -> UDPIPEncap(192.168.1.1, 4000, 192.168.1.2, 53)
  -> MarkIPHeader -> cH :: Counter -> req;
RatedSource(LENGTH 22, RATE 30) -> UDPIPEncap(192.168.1.2, 53, 192.168.1.1, 4000)
  -> MarkIPHeader -> cR :: Counter -> rep;

req -> [0]R1[0] -> [0]R3[0] -> Discard;
Idle -> [0]R2[0] -> Discard;
Idle -> [0]R4[0] -> Discard;
rep -> [1]R2[1] -> [1]R4[1] -> Discard;

DriverManager(wait 10s, print "=== counts", print cA.count, print cH.count, print cR.count,
              write R1.export, write R2.export, write R3.export, write R4.export,
              print "=== end", stop);
