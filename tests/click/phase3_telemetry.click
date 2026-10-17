// Phase 3 Click integration test (NOT an experiment). Loopback only.
//
// Five monitors see identical packets and export telemetry to 127.0.0.1:
//   mP  ROUTER_ID 1  V1  PARTITION
//   mL  ROUTER_ID 2  V1  LEAVES
//   mA  ROUTER_ID 3  V1  ALL
//   mS  ROUTER_ID 4  V1  PARTITION, inputs SWAPPED (direction-mapping control)
//   mX  paper format (no router id), LEAVES, to $PPORT
//
// Traffic (synthetic, generated in this process):
//   A  10.0.0.1    -> 18.0.0.1      2000 pps  request path  (starts 0.3 s, stops 3.3 s)
//   H  192.168.1.1 -> 10.9.9.9       100 pps  request path
//   R  10.9.9.9    -> 192.168.1.1     30 pps  reply path    (H's two-way session)
//   C  172.16.0.1  -> 172.16.0.9     200 pps  reply path
// Request path = input 0 of mP/mL/mA/mX, input 1 of mS. Reply path = the opposite.

define($PORT 49555, $PPORT 49556);

mP :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 0.5, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 1, BOOT_ID 1001);
mL :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 0.5, EXPORT LEAVES,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 2, BOOT_ID 1002);
mA :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 0.5, EXPORT ALL,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 3, BOOT_ID 1003);
mS :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 0.5, EXPORT PARTITION,
                        AGGREGATOR 127.0.0.1:$PORT, ROUTER_ID 4, BOOT_ID 1004);
mX :: CoopIPRateMonitor(PACKETS, 1, 50, 0, false, INTERVAL 0.5, EXPORT LEAVES, FORMAT PAPER,
                        AGGREGATOR 127.0.0.1:$PPORT);

req :: Null;
rep :: Null;

srcA :: RatedSource(LENGTH 22, RATE 2000, ACTIVE false)
  -> UDPIPEncap(10.0.0.1, 5000, 18.0.0.1, 80) -> MarkIPHeader -> cA :: Counter -> req;
srcH :: RatedSource(LENGTH 22, RATE 100)
  -> UDPIPEncap(192.168.1.1, 4000, 10.9.9.9, 53) -> MarkIPHeader -> cH :: Counter -> req;
srcR :: RatedSource(LENGTH 22, RATE 30)
  -> UDPIPEncap(10.9.9.9, 53, 192.168.1.1, 4000) -> MarkIPHeader -> cR :: Counter -> rep;
srcC :: RatedSource(LENGTH 22, RATE 200)
  -> UDPIPEncap(172.16.0.1, 80, 172.16.0.9, 5000) -> MarkIPHeader -> cC :: Counter -> rep;

req -> [0]mP[0] -> [0]mL[0] -> [0]mA[0] -> [1]mS[1] -> [0]mX[0] -> Discard;
rep -> [1]mP[1] -> [1]mL[1] -> [1]mA[1] -> [0]mS[0] -> [1]mX[1] -> Discard;

DriverManager(
  wait 0.3s, write srcA.active true,
  wait 3s,   write srcA.active false,
  wait 2.7s,
  write srcH.active false, write srcR.active false, write srcC.active false,
  write mP.export, write mL.export, write mA.export, write mS.export, write mX.export,
  print "=== counts", print cA.count, print cH.count, print cR.count, print cC.count,
  print "=== tx", print mP.tx_datagrams, print mL.tx_datagrams, print mA.tx_datagrams,
  print mS.tx_datagrams, print mX.tx_datagrams,
  print "=== tx_bytes", print mP.tx_bytes, print mL.tx_bytes, print mA.tx_bytes,
  print mS.tx_bytes, print mX.tx_bytes,
  print "=== tx_failures", print mP.tx_failures, print mL.tx_failures, print mA.tx_failures,
  print mS.tx_failures, print mX.tx_failures,
  print "=== end",
  stop);
