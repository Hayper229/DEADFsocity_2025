#!/bin/python3
import requests
import colorama
yellow = colorama.Fore.LIGHTYELLOW_EX
red = colorama.Fore.RED
green = colorama.Fore.GREEN
magneta = colorama.Fore.LIGHTMAGENTA_EX
def hlp():
    print('''Usage: ./DorkingScriptArg.py   URL Type targets protocols:  http://example.com/  or  https://example.com/ ''')



img_display=(f"{colorama.Back.BLACK}{colorama.Fore.RED}"+'''
                                                                               mmmm      m
   mmmm                         "                   mmmm                  "    #" "#   mm#mm
   #   "m  mmm    m mm   mmm   mmm    m mm    mmmm  #"   "  mmm    m mm  mmm   #    #    #
   #    # #" "#   #"  " #"  "    #    #"  #  #" "#  "#mmm  #"  "   #"  "   #   ##m#"     #
   #    # #   #   #     #        #    #   #  #   #      "# #       #       #   #         "mm
   #mmm"  "#m#"   #     "#mm"  mm#mm  #   #  "#m"#  "mmm#" "#mm"   #     mm#mm "
                                              mmm#

+===================================================================+
|        [Developer: https://github.com/Hayper229]                  |
+-------------------------------------------------------------------+
|                                                                   |
|                        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿                   |
|                        ⣿⣿⣿⣿⣿⣿⣿⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⣿⣿⣿⣿⣿⣿⣿                   |
|                        ⣿⣿⣿⣿⣿⣿⣿⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣿⣿⣿⣿⣿⣿⣿                   |
|                        ⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿                   |
|                        ⣿⣿⡿⠛⠉⣁⣀⣠⣴⣿⣿⣿⣿⣿⣿⣦⣄⣀⣈⡉⠙⠻⣿⣿                   |
|                        ⣿⠏⢠⣾⣿⣿⣿⣿⣿⠟⠋⠉⠉⠉⠛⢿⣿⣿⣿⣿⣷⣆⠘⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⡿⠁⠄⠄⠄⠄⠄⠄⠄⠹⣿⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⠁⠄⠄⡀⠄⠄⢀⡀⠄⠄⢹⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⡀⠄⢾⣿⠆⠄⣿⡿⠄⠄⣸⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⣿⣦⡀⠄⢠⡆⠄⠄⣠⣾⣿⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⣿⣿⣷⣀⣚⣛⣀⣰⣿⣿⣿⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣿⣿⣿⣿⣿⠏⠛⠛⠛⠛⠛⢿⣿⣿⣿⣿⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⡇⠄⠉⠛⠿⢿⣶⣶⣶⣶⣾⠿⠛⠋⠁⠈⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⣷⣶⣶⣶⣤⣤⣀⡈⠉⠛⠛⠿⠿⢷⣶⣶⣿⣿⠄⣿                   |
|                        ⣿⠄⢸⣿⡇⠄⠄⣠⣭⣿⣿⣿⣿⣷⣶⣤⣄⡀⠄⢀⣿⣿⠄⣿                   |
|                        ⣿⡄⠸⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣾⣿⡟⢀⣿                   |
|                        ⣿⣿⣄⡈⠙⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⢉⣠⣾⣿                   |
|                        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿                   |
+-------------------------------------------------------------------+
|===================================================================|
|                 DorkingScript-Version > FullConsole               |
+-------------------------------------------------------------------+


''')




def main(url: str):
    print(img_display)
    hlp()
    print('please enter url | URL examples <http://example.com/ | https://example.com/')
    codes = [200, 300, 301, 302, 303]
    with open('testlist.txt', 'r') as f:
         save = f.read()
         savef = save.split()
         print(f'{green}[{yellow}!{green}[{red}Search for directories and files{green}]{yellow}!{green}]{red}')
         url = url.rstrip('/')
         for file in savef:
             main_url=url+'/'+file
             try:
                resp = requests.get(main_url)
             except Exception as e:
                    print(f'{yellow}Error {red}{e}{red}')
                    pass
             for code in codes:
                 if resp.status_code == code:
                    print(f'\n{green}[{red}DIR{yellow}\{red}FILE{green}]{magneta}: {yellow}/{file}')
                    print(f'{green}[{red}URL{green}]{magneta}: {yellow}{resp.url} {green}[{red}CODE{green}]{magneta}: {colorama.Fore.LIGHTGREEN_EX}{resp.status_code}{red}')
                    break




if __name__ == "__main__":
   url = input('@DSARG > ')
   main(url)
