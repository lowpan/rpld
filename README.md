# lowpan/RPLD

This repository is a improvement of [linux-wpan/rpld](https://github.com/linux-wpan/rpld) implementing encryption schemes on the RPL protocol.

# Dependencies

- lua (version >= XXX) for config parsing
- libev (version >= XXX) for high level timer, loop handling
- mnl (version >= XXX) for high level netlink handling
- [mininet-wifi](https://github.com/intrig-unicamp/mininet-wifi)
- python 3

# Build

$ git submodule update --init --recursive

$ mkdir build

$ meson build

$ ninja -C build

# Testing

There is three scenarios that can be tested with the use of mininet-wifi:

- test/mininet/6LoWPan-None.py
  This test perfoms the rpl protocol without any assymetric encryption
- test/mininet/6LoWPan-kyber.py
  This test performs the rpl protocol with the use of Kyber assymetric encryption
- test/mininet/6LoWPan-RSA.py
  This test performs the rpl protocol with the use of RSA assymetric encryption

To run you simply do ```sudo python3 6LoWPan-<mode>.py -r```

This will start the mininet with the RPL protocol running. In the scenerios there are two sensors: sensor1 and sensor2.

To see the rpl packet exchange, you can access one of the sensors with xterm and run wireshark on it.

Ex:
```
mininet-wifi> xterm sensor1
wireshark &
``` 

If you desire to restart the RPL and see the key exchange, you shall enter the sensors with xterm and kill the current rpld processes. You can do it with ps aux and kill commands. After killing the current commands, you run the rpld with ```rpld -C lowpan-sensor<number>.conf```

Ex:
```
mininet-wifi> xterm sensor1
ps aux
kill 9 # Random number for rpld process
rpld -C lowpan-sensor1.conf
```

## Parameters

The Kyber and RSA encryptions are parametric in the way that you can use Kyber512, Kyber768, Kyber1024, RSA1024 and RSA2048.

To change the parameter of Kyber you must go to crypto/kyber/ref/params.h and change the parameter **KYBER_K**, the value of the parameter can be 2, 3 or 4 in respect to the lower to highest levels of security.

To change the parameter os RSA you must go to helpers.h and change the parameter **RSA_MODE**, the value of the parameter can be 1 or 2 in respect to RSA1024 and RSA2048.
