#!/usr/bin/env python3
# -----------------------------------------------------------
# RECON TOOLKIT v2.0 — Ethical Information Gathering Suite
# Author: Rxxxxxx 
# -----------------------------------------------------------

import socket
import requests
import dns.resolver
import whois
from bs4 import BeautifulSoup

# -----------------------------------------------------------
# 1) DNS LOOKUP MODULE
# -----------------------------------------------------------
def dns_lookup(domain):
    print("\n=== DNS Lookup ===")
    records = ["A", "MX", "NS", "TXT"]
    for rec in records:
        try:
            answers = dns.resolver.resolve(domain, rec)
            for ans in answers:
                print(f"{rec}: {ans}")
        except:
            pass

# -----------------------------------------------------------
# 2) WHOIS LOOKUP MODULE
# -----------------------------------------------------------
def whois_lookup(domain):
    print("\n=== WHOIS Information ===")
    try:
        info = whois.whois(domain)
        print(info)
    except:
        print("WHOIS lookup failed.")

# -----------------------------------------------------------
# 3) PORT SCANNER MODULE
# -----------------------------------------------------------
def port_scan(target):
    print("\n=== Port Scan (Top Ports) ===")
    ports = [21,22,23,25,53,80,110,139,443,445,3306,8080]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
            sock.close()
        except:
            pass

# -----------------------------------------------------------
# 4) SUBDOMAIN ENUMERATION MODULE
# -----------------------------------------------------------
def subdomain_enum(domain):
    print("\n=== Subdomain Enumeration ===")
    subs = ["www", "mail", "ftp", "cpanel", "blog", "dev", "test"]
    for sub in subs:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print("[FOUND] ", subdomain)
        except:
            pass

# -----------------------------------------------------------
# 5) DIRECTORY BRUTEFORCE MODULE
# -----------------------------------------------------------
def directory_bruteforce(url):
    print("\n=== Directory Bruteforce ===")
    dirs = ["admin", "login", "test", "backup", "config"]
    if not url.endswith("/"):
        url += "/"
    for d in dirs:
        full = url + d
        r = requests.get(full)
        if r.status_code == 200:
            print("[FOUND]", full)

# -----------------------------------------------------------
# 6) TECHNOLOGY DETECTION MODULE
# -----------------------------------------------------------
def tech_detect(url):
    print("\n=== Tech Detection ===")
    try:
        r = requests.get(url)
        print("Server:", r.headers.get("Server"))
        print("X-Powered-By:", r.headers.get("X-Powered-By"))
    except:
        print("Could not fetch headers.")

# -----------------------------------------------------------
# 7) IP GEOLOCATION MODULE
# -----------------------------------------------------------
def ip_geolocate(ip):
    print("\n=== IP Geolocation ===")
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}").json()
        for k,v in data.items():
            print(k, ":", v)
    except:
        print("Geolocation failed.")

# -----------------------------------------------------------
# 8) EMAIL SCRAPER MODULE
# -----------------------------------------------------------
import re
def email_scraper(url):
    print("\n=== Email Scraper ===")
    try:
        html = requests.get(url).text
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html))
        for e in emails:
            print(e)
    except:
        print("Scraping failed.")

# -----------------------------------------------------------
# 9) USERNAME CHECKER (SOCIAL)
# -----------------------------------------------------------
def username_check(user):
    print("\n=== Username Social Check ===")
    sites = {
        "GitHub": f"https://github.com/{user}",
        "Instagram": f"https://instagram.com/{user}",
        "Twitter": f"https://twitter.com/{user}"
    }
    for name, link in sites.items():
        r = requests.get(link)
        if r.status_code == 200:
            print(f"[FOUND] {name}: {link}")

# -----------------------------------------------------------
# MENU SYSTEM
# -----------------------------------------------------------
def menu():
    print("""
=====================================================
         RECON TOOLKIT - ETHICAL VERSION
=====================================================
1. DNS Lookup
2. WHOIS Lookup
3. Port Scan
4. Subdomain Enumeration
5. Directory Bruteforce
6. Technology Detection
7. IP Geolocation
8. Email Scraper
9. Username Finder
0. Exit
""")

    choice = input("Select option: ")

    if choice == "1":
        dns_lookup(input("Domain: "))
    elif choice == "2":
        whois_lookup(input("Domain: "))
    elif choice == "3":
        port_scan(input("Target IP/Domain: "))
    elif choice == "4":
        subdomain_enum(input("Domain: "))
    elif choice == "5":
        directory_bruteforce(input("URL: "))
    elif choice == "6":
        tech_detect(input("URL: "))
    elif choice == "7":
        ip_geolocate(input("IP: "))
    elif choice == "8":
        email_scraper(input("URL: "))
    elif choice == "9":
        username_check(input("Username: "))
    elif choice == "0":
        exit()

# MAIN LOOP
while True:
    menu()
