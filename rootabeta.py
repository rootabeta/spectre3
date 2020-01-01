import sys
import telnetlib

def py_version(): 
    return sys.version_info[0]

def print_color_table():
    """
    prints table of formatted text format options
    """
    for style in range(8):
        for fg in range(30,38):
            s1 = ''
            for bg in range(40,48):
                format = ';'.join([str(style), str(fg), str(bg)])
                s1 += '\x1b[%sm %s \x1b[0m' % (format, format)
            print(s1)
        print('\n')

class color:
    red    = '\033[91m'
    yellow = '\033[93m'
    green  = '\033[92m'
    bold   = '\033[1m'
    light_purple = '\033[94m'
    purple = '\033[95m'
    end    = '\033[0m'
    blink = '\33[5m'
    italic = '\33[3m'

class log:
    def warn(string):
        print("{}[WARN]{} {}".format(color.yellow,color.end,string))
    def error(string):
        print("{}[!]{} {}".format(color.red,color.end,string))
    def info(string):
        print("[*] {}".format(string))
    def success(string):
        print("{}[+]{} {}".format(color.green,color.end,string))


class full_color:
    end      = '\33[0m'
    bold     = '\33[1m'
    italic   = '\33[3m'
    url      = '\33[4m'
    blink    = '\33[5m'
    blink2   = '\33[6m'
    selected = '\33[7m'

    black  = '\33[30m'
    red    = '\33[31m'
    green  = '\33[32m'
    yellow = '\33[33m'
    blue   = '\33[34m'
    violet = '\33[35m'
    beige  = '\33[36m'
    white  = '\33[37m'

    blackbg  = '\33[40m'
    redbg    = '\33[41m'
    greenbg  = '\33[42m'
    yellowbg = '\33[43m'
    bluebg   = '\33[44m'
    violetbg = '\33[45m'
    beigebg  = '\33[46m'
    whitebg  = '\33[47m'

    grey    = '\33[90m'
    red2    = '\33[91m'
    green2  = '\33[92m'
    yellow2 = '\33[93m'
    blue2   = '\33[94m'
    violet2 = '\33[95m'
    beige2  = '\33[96m'
    white2  = '\33[97m'

class graphics:
    granted = """=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
-=-=-=-=-= ACCESS  GRANTED =-=-=-=-=-
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="""

    denied = """=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
-=-=-=-=-=- ACCESS DENIED -=-=-=-=-=-
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="""



colour = color
full_colour = full_color #Cross-compatability :)

def interact(socket):
    t = telnetlib.Telnet()
    t.sock = socket
    t.interact()

def read_until(socket,string):
    buf = ""
    while string not in buf:
        buf += socket.recv(1)
    return buf

def decode_bytes(b_obj,encoding='utf-8'):
    return b_obj.decode(encoding)
    
def encode_bytes(b_obj,encoding='utf-8'):
    return b_obj.encode(encoding)


