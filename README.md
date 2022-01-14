# sniper
Sniper is a command line tool that sniffs it locally for active TCP connections and sends RST packets to force those connections to terminate. This can be described as a program that generates a single packet DoS attack.


Sending spurious RST Packets can be used for malicious purposes (e.g., DoS attack [1,4]) or closing down suspicious connections. In recent years, it has been used by ISPs to close down P2P connections (e.g., by [Comcast] (http://en.wikipedia.org/wiki/Comcast#Network_neutrality)).


## Build

#### ubuntu
```
sudo apt -y install libpcap-dev
make
```

## How to Use

```
nc -klv 11111
```

```
# Force close ACK sessions.

./sniper lo "(tcp[13] == 0x10)"
```

```
lsof -i4:11111 -P
nc -v <SERVER_ADDR> 11111
```

