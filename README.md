## Introduction

When using **smartproxy** as your system's default proxy, it can redirect traffic on user rules, 
whether direct connect or through another backend proxy.

**smartproxy** accepts HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5 as incoming connections and connects backend proxy with SOCKS5.

**smartproxy** also redispatches HTTP requests, so some old HTTP clients without keep-alive support will enjoy huge performance boost.

## QuickStart
* Make sure you have **[Java](https://java.com/) 8+** installed
* [Download latest build](https://github.com/Immueggpain/smartproxy/releases). Unzip it
* Setup your backend proxy, supposedly ss, to use 127.0.0.1:1080
* Run `java -jar smartproxy-x.x.x.jar`. x.x.x is the version you downloaded
* Set your system proxy to 127.0.0.1:1082
* Enjoy!

## settings.json
**smartproxy** automatically uses settings.json file in current working directory as config file.  
Here are the default values. Modify it if you need.
```json
{
	"local_listen_port": 1082,
	"local_listen_ip": "127.0.0.1",
	"backend_proxy_port": 1080,
	"backend_proxy_ip": "127.0.0.1"
}
```

## user.rule
**smartproxy** automatically uses user.rule file in current working directory as routing configuration.  
```
# A line which starts with "#" is comment
# "a.com" means "a.com" only, ".a.com" means "a.com" and all sub domains of "a.com" 
# "direct" means connect without proxy
# "proxy" means forward to backend proxy
# "reject" means drop connection
```
For example, when deciding routes of **sub.domain.com**, smartproxy first checks if there's a **sub.domain.com** rule.  
Then it checks **.sub.domain.com**. Then **.domain.com**. Then **.com**.  
And lastly, if all miss, it uses default rule, which is **proxy**.

## Build
You need [**Maven**](https://maven.apache.org/) to build **smartproxy**.  
Just run `maven install` and you will find the jar and zip generated in the `target` folder.  
You can also import the project using [**Eclipse**](https://www.eclipse.org/).
