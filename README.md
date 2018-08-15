## Introduction

When using **smartproxy** as your system's default proxy, it can redirect traffic on user rules, 
whether direct connect or through another backend proxy.

**smartproxy** accepts HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5 as incoming connections and connects backend proxy with SOCKS5.

## QuickStart
* Make sure you have java 8+ installed
* Download latest build
* Setup your backend proxy to use 127.0.0.1:1080
* Run `java -jar smartproxy-x.x.x.jar`
* Set your system proxy to 127.0.0.1:1082
* Enjoy!
