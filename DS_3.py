#!/bin/python3
import time
import requests
from threading import Thread
import os
import socket
import whois as wh
import phonenumbers
import dns
import dns.resolver
import scapy.all as scapy
import colorama
from colorama import init
init()
from colorama import Fore, Back, Style
#cls = lambda:if os.name == "nt" else os.system("clear")
#print(Style.BRIGHT +


def whois_info():
    url = input("URL_OR_Domain: ")
    whois_url = wh.whois(url)
    dom = wh.extract_domain(url)
    print("[Подсказка]: Чтобы прирвать программу нажмите CTRL+C")
    print(f'[URL]: {url}\n[WhoIs_URL]: {whois_url}\n[Extract Domain]: {wh.extract_domain(url)}\n[Whois Domain]: {wh.whois(dom)}\nIP: {socket.gethostbyname(dom)}\nIPs: {socket.gethostbyname_ex(dom)}{Fore.YELLOW}')
    entern = input("Посмотреть информацию по IP? Y/n: ")
    enter = entern.lower()
    if enter == "n":
       print('Exit..');exit()
    elif enter == 'y':
       while True:
             ip = input("IP: ")
             print(f'[Полученая информация об  IP host]: {socket.gethostbyaddr(ip)}')
             if ip:
                pass
             elif ip == 'exit':
                break;exit()
             elif ip == '':
                break;exit()


def ph():
    number = input('Введите номер телефона: ')
    try:
       phoneNumber = phonenumbers.parse(number)
       Carrier = carrier.name_for_number(phoneNumber, 'ru')
       Region = geocoder.description_for_number(phoneNumber, 'ru')
       TimeZone = timezone.time_zones_for_number(phoneNumber)
       valid = phonenumbers.is_valid_number(phoneNumber)
       print(valid)
       if valid:
          print(Carrier, Region, TimeZone)
    except Exception as e:
           print(f'Error: {e}')


def dnsinf():
     domain=input('[*] Domain: ')
     if domain:
        try:
           result = dns.resolver.resolve(domain, 'A')
           for ipval in result:
               print('IP', ipval.to_text())
        except Exception as e:
               print(f'Error: {e}')


def sniff_start():
    proto = str(input('Protocols: ARP, TCP, IP, или  None: '))
    protocols = ['arp', 'tcp', 'ip', 'none']
    if proto:
       if porot in protocols:
          packages = int(input('Packages: '))
          try:
             pack =  scapy.sniff(packages, proto)
             print(f'{colorama.Fore.LIGHTBLACK_EX}[{colorama.Fore.LIGHTBLUE_EX}*{colorama.Fore.LIGHTBLACK_EX}]{colorama.Fore.LIGHTYELLOW_EX} Selected Protocol {colorama.Fore.LIGHTYELLOW_EX}: {proto}\n{colorama.Fore.LIGHTYELLOW_EX} Selected number of packages{colorama.Fore.LIGHTYELLOW_EX}: {packages}')
             pack.summary()
          except Exception as e:
                 print('Error:', e)


def source_ip():
    domain = str(input('Domain: '))
    if domain:
       try:
          print(f'Domain: {domain}\nIP: {socket.gethostbyname(domain)}')
       except Exception as e:
              print(f'Error: {e}')


def hlp():
    yellow = colorama.Fore.LIGHTYELLOW_EX
    red = colorama.Fore.RED
    green = colorama.Fore.GREEN
    magneta = colorama.Fore.LIGHTMAGENTA_EX
    print('''Usage: ./DorkingScriptArg.py   URL Type targets protocols:  http://example.com/  or  https://example.com/ ''')
    img_display=(f"{colorama.Back.BLACK}{colorama.Fore.RED}"+f'''
                                                                               mmmm      m
   mmmm                         "                   mmmm                  "    #" "#   mm#mm
   #   "m  mmm    m mm   mmm   mmm    m mm    mmmm  #"   "  mmm    m mm  mmm   #    #    #
   #    # #" "#   #"  " #"  "    #    #"  #  #" "#  "#mmm  #"  "   #"  "   #   ##m#"     #
   #    # #   #   #     #        #    #   #  #   #      "# #       #       #   #         "mm
   #mmm"  "#m#"   #     "#mm"  mm#mm  #   #  "#m"#  "mmm#" "#mm"   #     mm#mm "
                                              mmm#

+===================================================================+
|       {colorama.Fore.GREEN}[{colorama.Fore.LIGHTYELLOW_EX}Developer{colorama.Fore.LIGHTMAGENTA_EX}: {colorama.Fore.LIGHTYELLOW_EX}https://github.com/Hayper229{colorama.Fore.GREEN}]{colorama.Back.BLACK}{colorama.Fore.RED}                   |
+-------------------------------------------------------------------+
|===================================================================|
|                {colorama.Fore.GREEN}DorkingScript-Version {colorama.Fore.LIGHTMAGENTA_EX}> {colorama.Fore.LIGHTYELLOW_EX}FullConsole{colorama.Back.BLACK}{colorama.Fore.RED}                |
+-------------------------------------------------------------------+
''')
    print(img_display)

def main_func(url: str, wordlist: str):
    hlp()
    print('Please enter url | URL examples <http://example.com/ | https://example.com/')
    wordlist = wordlist
    if not os.path.exists(wordlist):
       print('Wordlist not found.')
    else:
        codes = [200, 300, 301, 302, 303]
        with open(f'{wordlist}', 'r') as f:
             save = f.read()
             savef = save.split()
             print(f'{colorama.Fore.GREEN}[{colorama.Fore.LIGHTYELLOW_EX}!{colorama.Fore.GREEN}[{colorama.Fore.RED}Search for directorys and files{colorama.Fore.GREEN}]{colorama.Fore.LIGHTYELLOW_EX}!{colorama.Fore.GREEN}]{colorama.Fore.RED}')
             url = url.rstrip('/')
             for file in savef:
                 main_url=url+'/'+file
                 try:
                    resp = requests.get(main_url)
                 except Exception as e:
                        print(f'{colorama.Fore.LIGHTYELLOW_EX}Error {colorama.Fore.RED}{e}{colorama.Fore.RED}')
                        pass
                 for code in codes:
                     if resp.status_code == code:
                        print(f'\n{colorama.Fore.GREEN}[{colorama.Fore.RED}DIR{colorama.Fore.LIGHTYELLOW_EX}\{colorama.Fore.RED}FILE{colorama.Fore.GREEN}]{colorama.Fore.LIGHTMAGENTA_EX}: {colorama.Fore.LIGHTYELLOW_EX}/{file}')
                        print(f'{colorama.Fore.GREEN}[{colorama.Fore.RED}URL{colorama.Fore.GREEN}]{colorama.Fore.LIGHTMAGENTA_EX}: {colorama.Fore.LIGHTYELLOW_EX}{resp.url} {colorama.Fore.GREEN}[{colorama.Fore.RED}CODE{colorama.Fore.GREEN}]{colorama.Fore.LIGHTMAGENTA_EX}: {colorama.Fore.LIGHTGREEN_EX}{resp.status_code}{colorama.Fore.RED}')
                        break



def DorkingScriptFunc():
    try:
       url = input('@DSARG > ')
       wordlist = input('Enter your wordlist: ')
       main_func(url, wordlist)
    except:
          print('Введите URL!')
          url = input('@DSARG > ')
          main_func(url)


def logo():
    print(f"{Back.BLACK}{Fore.GREEN}"+'''

 ____  _____    _    ____  _____               _ _
|  _ \| ____|  / \  |  _ \|  ___|__  ___   ___(_) |_ _   _
| | | |  _|   / _ \ | | | | |_ / __|/ _ \ / __| | __| | | |
| |_| | |___ / ___ \| |_| |  _|\__ \ (_) | (__| | |_| |_| |
|____/|_____/_/   \_\____/|_|  |___/\___/ \___|_|\__|\__, |
                                                     |___/
''')
print(Fore.RED+"[",Fore.BLUE+"Developer",Fore.WHITE+"->",Fore.YELLOW+"Hayper229",Fore.RED+"]")
print(Fore.RED+"[",Fore.YELLOW+"GitHub",Fore.WHITE+"->",Fore.YELLOW+"https://github.com/Hayper229",Fore.RED+"]")
def menu():
     print('''[+] 1 Dos Requests response on tls 1-3 and http
[+] 2 DosFlood http, https
[+] 3 TCPDosFlood http, https
[+] 4 source ip address site
[+] 5 Sniffer [root]
[+] 6 Scanner
[+] 7 Parser
[+] 8 PNum
[+] 9 UDPDosser UDP, TCP, TLSv1.1, TLSv1.2, TLSv1.3
[+] 10 DorkingScriptConsole   Finding directorys and files
[+] 11 PHParser
[+] 12 DNSinfo
[+] 13 Whois
''')
def main():
    a = int(input(Fore.RED+"Enter->>: "))
    if a <= 0:print('[!] Selection Error')
    elif a == 0:exit() and os.system("clear")
    elif a == 1:os.system('./Rdos.py')
    elif a == 2:os.system('./DosFM.py')
    elif a == 3:os.system('./TCPflood.py')
    elif a == 4:source_ip()
    elif a == 5:sniff_start()
    elif a == 6:os.system('./scanner.py')
    elif a == 7:os.system('./pars.py')
    elif a == 8:ph()
    elif a == 9:os.system('./UDPDosser.py  ')
    elif a == 10:DorkingScriptFunc()
    elif a == 11:os.system('./parser.php')
    elif a == 12:dnsinf()
    elif a == 13:whois_info()
    elif a > 13:print('[!] Selection Error')

def union():
     logo()
     menu()
     main()


#union()
while True:
      union()
      break
