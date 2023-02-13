
<p align="center">
  <img width="460" height="auto" src="https://user-images.githubusercontent.com/110246050/215688266-a8aacee4-9e47-4f9a-92d1-961b61812ec4.png">
</p>
<p align="center">
<a href="#"><img src="https://img.shields.io/badge/contributors-1-green" alt=""></a>
<a href="#"><img src="https://img.shields.io/badge/developing-stable-green" alt=""></a>
<a href="#"><img src="https://img.shields.io/badge/version-v0.1.0-blue" alt=""></a>
<a href="https://twitter.com/intent/follow?screen_name=drfabiocastro">
<img src="https://img.shields.io/twitter/follow/drfabiocastro?style=social&logo=twitter" alt="follow on Twitter"></a>
</p>

<p align="justify">
CertWatcher is a tool for capturing and tracking certificate transparency logs, using YAML templates and Selenium. The tool helps to detect and analyze phishing sites, and is designed to make it easy to use for security professionals and researchers.
</p>
<p align="center">
<img width="780" height="auto" src="https://user-images.githubusercontent.com/110246050/216151671-66e7cc76-0c31-42e7-aab5-97e46ec039d9.jpg">
<br>
<em>Simple flowchart of how Certwatcher works.</em>
</p>
<p align="justify">
Certwatcher continuously monitors the certificate data stream and checks for suspicious patterns or malicious activity. If a threat is detected, the tool can take measures to prevent the attack, such as blocking the website or sending a notification. Certwatcher can also be customized to detect specific phishing patterns and combat the spread of malicious websites through online advertisements. Furthermore, Selenium is used to automate web tests and collect data on websites, which is essential for accurate and efficient detection of cyber attacks.
<p>


# Certwatcher Installation Guide

Welcome to the Certwatcher Installation Guide. In this guide, we will walk you through the process of installing the Certwatcher application.


## Requirements
- Go 1.13 or later
- Git
## Installing

```bash
  git clone https://github.com/drfabiocastro/certwatcher.git
  cd certwatcher
  make build
  sudo make install
```
*This will install the Certwatcher binary at /usr/bin/certwatcher. You can now run the Certwatcher binary from any location.*


## Running Certwatcher
*You can run the Certwatcher binary by executing the following command:*
```bash
$ certwatcher

```
## Authors

- [@drfabiocastro](https://www.twitter.com/drfabiocastro)

