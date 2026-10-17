// Phase 2 Click smoke / equivalence test (NOT an experiment).
//
// Every packet passes through upstream IPRateMonitor ("up") and then through
// two CoopIPRateMonitor instances: "coop" (same parameters as up, export timer
// every 1 s) and "tot" (no timer; exported once at the end so its window
// counts cover the whole run). tests/click/check_equivalence.py compares
// up.look with coop.look and the exact counts in tot with Counter elements.
//
// Traffic (synthetic, generated inside this process only):
//   A  10.0.0.1    -> 18.0.0.1     10000 pps  input 0 (forward, keyed by src)
//   B  192.168.1.1 -> 192.168.1.2     50 pps  input 0
//   C  172.16.0.1  -> 172.16.0.9     200 pps  input 1 (reverse, keyed by dst)

up   :: IPRateMonitor(PACKETS, 1, 100, 0, false);
coop :: CoopIPRateMonitor(PACKETS, 1, 100, 0, false, INTERVAL 1);
tot  :: CoopIPRateMonitor(PACKETS, 1, 100, 0, false);

srcA :: RatedSource(LENGTH 22, RATE 10000)
  -> UDPIPEncap(10.0.0.1, 5000, 18.0.0.1, 80) -> MarkIPHeader -> cA :: Counter -> [0]up;
srcB :: RatedSource(LENGTH 22, RATE 50)
  -> UDPIPEncap(192.168.1.1, 5000, 192.168.1.2, 80) -> MarkIPHeader -> cB :: Counter -> [0]up;
srcC :: RatedSource(LENGTH 22, RATE 200)
  -> UDPIPEncap(172.16.0.1, 80, 172.16.0.9, 5000) -> MarkIPHeader -> cC :: Counter -> [1]up;

up[0] -> [0]coop[0] -> [0]tot[0] -> Discard;
up[1] -> [1]coop[1] -> [1]tot[1] -> Discard;

DriverManager(
  wait 5s,
  write srcA.active false, write srcB.active false, write srcC.active false,
  write tot.export,
  print "=== up.look", print up.look,
  print "=== coop.look", print coop.look,
  print "=== coop.exports", print coop.exports,
  print "=== coop.stats", print coop.stats,
  print "=== tot.snapshot", print tot.snapshot,
  print "=== counts", print cA.count, print cB.count, print cC.count,
  stop);
