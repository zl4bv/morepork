# Morepork

OpenFlow/Ryu application to detect and mitigate distributed denial of service (DDoS) attacks on-the-wire.

  - Detects spikes and unexpected increases in load
  - Identifies attacks using out-of-box intrusion detection systems (IDSs)
  - Drops attack traffic on-the-wire


## Version

0.1


## Tech

Morepork uses a number of open source projects to work properly:

* [Ryu] - OpenFlow controller written in Python
* [Security Onion] - Linux distro for IDS, NSM, and log management


## Installation

```sh
git clone https://github.com/zl4bv/morepork.git
cd morepork
sudo pip install -r requirements.txt
```

## Running Morepork

```sh
cd morepork
TRIPWIRE_CONF=config/tripwire.yaml ryu-manager morepork.app.main
```

## License

New BSD License


[Ryu]:https://github.com/osrg/ryu
[Security Onion]:http://blog.securityonion.net/p/securityonion.html
