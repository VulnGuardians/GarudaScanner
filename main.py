### Database Setup for Garuda Scanner ###

import sqlite3

connection = sqlite3.connect('garuda.db')
cursor = connection.cursor()

cursor.execute('CREATE TABLE "contact_us753" ("id"	INTEGER NOT NULL,"name"	text NOT NULL,"email" text NOT NULL,"message" text NOT NULL, PRIMARY KEY("id" AUTOINCREMENT));')

data = [
    (101, "Nmap", "nmap -sV --script=vuln -A -o -Sc -T4"),
    (102, "WhatWeb", "whatweb -vv -a 3"),
    (103, "WpScan", "wpscan --url"),
    (104, "FFuF", "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u"),
    (105, "SqlMap", "sqlmap --dump-all --risk 3 --level 3 --url"),
    (106, "Owasp Zap", "zaproxy"),
    (107, "SearchSploit", "searchsploit"),
    (108, "dirb", "dirb"),
    (109, "Nikto", "nikto --host")
]

connection.close()