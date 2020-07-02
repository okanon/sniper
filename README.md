# sniper
Sniper is a command line tool that sniffs it locally for active TCP connections and sends RST packets to force those connections to terminate. This can be described as a program that generates a single packet DoS attack.


Sending spurious RST Packets can be used for malicious purposes (e.g., DoS attack [1,4]) or closing down suspicious connections. In recent years, it has been used by ISPs to close down P2P connections (e.g., by [Comcast] (http://en.wikipedia.org/wiki/Comcast#Network_neutrality)).
