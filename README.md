## Introduction 

**A naive forwarding protocol. This is a proof of concept (PoC).**

- follows 0-RTT pattern.
- forward on rules.
- handles http connect and socks requests.
- also redispatches HTTP requests, so some old HTTP clients without keep-alive support will enjoy some performance boost.

## QuickStart
* Make sure you have **[Java](https://jdk.java.net/11/) 11+** installed. 
* Prepare a **valid** SSL cert at <cert_file> and its private key at <private_key_file>. The private key must be encoded in PEM.
* [Download latest build](https://github.com/Immueggpain/forwardproto/releases). Unzip it
* Run `java -jar smartproxy-x.x.x.jar help` to get help.
* Run client `java -jar smartproxy-x.x.x.jar client -n <local_listening_port> -p <server_listening_port> -s <server_ip> -w <secret_password>`.
* Run server `java -jar smartproxy-x.x.x.jar server -c <cert_file> -k <private_key_file> -p <server_listening_port> -w <secret_password>`.
* Use "socks5://127.0.0.1:<local_listening_port>"
* Enjoy!

## How to get SSL cert
see [certbot](https://certbot.eff.org/) ([github](https://github.com/certbot/certbot))

## user.rule
You may also update your user.rule file for better experience. Just download it and replace the old one.  
[The lastest user.rule can be downloaded here.](user.rule)  
**forwardproto** automatically uses user.rule file in current working directory as routing configuration.  
```
# A line which starts with "#" is comment
# "a.com" means "a.com" only, ".a.com" means "a.com" and all sub domains of "a.com" 
# we can also use ip range like "192.168.0.0 192.168.255.255"
#
# "direct" means connect without proxy
# "proxy" means forward to backend proxy
# "reject" means drop connection
```
For example, when deciding routes of **sub.domain.com**, first checks if there's a **sub.domain.com** rule.  
Then it checks **.sub.domain.com**. Then **.domain.com**. Then **.com**.  
And lastly, if all miss, it uses default rule, which is **proxy**.

## Build
You need [**Maven**](https://maven.apache.org/) to build.  
Just run `maven install` and you will find the jar and zip generated in the `target` folder.  
