import Foundation
import SentinelCore

// XCTest isn't available under CommandLineTools — this is a plain assert runner.
// Run: swift run sentinel-test

var failures = 0
func check(_ cond: Bool, _ name: String) {
    print(cond ? "  ok  \(name)" : "  FAIL \(name)")
    if !cond { failures += 1 }
}

// arp
let arp = """
? (192.168.1.1) at 80:2a:a8:5c:91:aa on en0 ifscope [ethernet]
? (192.168.1.34) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""
let t = Parse.arpTable(arp)
check(t["192.168.1.1"] == "80:2a:a8:5c:91:aa", "arp parses mac")
check(t["192.168.1.34"] == nil, "arp skips incomplete")
check(t["224.0.0.251"] == "1:0:5e:0:0:fb", "arp parses single-digit mac")

// route
let route = "   route to: default\ndestination: default\n      gateway: 192.168.1.1\n  interface: en0"
check(Parse.defaultGateway(route) == "192.168.1.1", "route parses gateway")
check(Parse.defaultGateway("route to: nowhere\n") == nil, "route missing gateway -> nil")

// scutil
let dns = """
DNS configuration
resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 1.1.1.1
resolver #2
  nameserver[0] : 192.168.1.1
"""
check(Parse.resolvers(dns) == ["192.168.1.1", "1.1.1.1"], "dns dedupes resolvers")

// lsof
let lsof = """
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google     1234 reddux   45u  IPv6 0xa1b2c3d4e5f6a7b8      0t0  TCP 192.168.1.5:52900->142.250.72.206:443 (ESTABLISHED)
com.apple   220 reddux   12u  IPv4 0xb2c3d4e5f6a7b8c9      0t0  UDP *:5353
"""
let conns = Parse.conns(lsof)
check(conns.count == 2, "lsof header skipped")
check(conns[0].proc == "Google" && conns[0].pid == 1234, "lsof proc+pid")
check(conns[0].node == "192.168.1.5:52900->142.250.72.206:443", "lsof remote node")
check(conns[1].node == "*:5353", "lsof udp node")

// severity ordering
check(Severity.critical > Severity.warning
      && Severity.warning > Severity.notice
      && Severity.notice > Severity.info,
      "severity orders critical > warning > notice > info")

print(failures == 0 ? "\nall checks passed" : "\n\(failures) check(s) failed")
exit(failures == 0 ? 0 : 1)
