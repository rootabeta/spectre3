from PyInquirer import prompt  #pip3 install pyinquirer
import readchar #pip3 install readchar
import sys

def list(question,choices):
    questions = [{'type':'list','name':'list','message':question,'choices':choices}]
    answers = prompt(questions)
    return answers['list']
def ask(question):
    questions = [{'type':'input','name':'ask','message':question}]
    answers = prompt(questions)
    return answers['ask']
def password(question="Please enter your password"):
    questions = [{'type':'password','name':'password','message':question}]
    answers = prompt(questions)
    return answers['password']

def getchar():
    c = readchar.readchar()
    return c

def getkey():
    k = readchar.readkey()
    return k

def silentinput():
    buf = ""
    stroke = ""
    while stroke != "\r" and stroke !="\n":
        if stroke == "\x03": #Ctrl-C
            raise KeyboardInterrupt
        else:
            buf += stroke
        stroke = getchar()
    return buf

def coinput(): #constantly updates
    print("BROKEN")
    return None
    buf = ""
    stroke = ""
    while stroke != "\r" and stroke !="\n":
        if stroke == "\x03": #Ctrl-C
            raise KeyboardInterrupt
        elif stroke == "\x7f": #backspace
            buf = buf[:-1]
            sys.stdout.write("\r")
            sys.stdout.write(buf)
            sys.stdout.write('\033[K')
            sys.stdout.flush()
            stroke = getchar()
        
        else:
            #debug = False
            debug = True 
            buf += stroke
            if debug:
                print(bytes(buf,encoding='utf-8').hex())
            sys.stdout.write("\r")
            sys.stdout.write(buf)
            sys.stdout.flush()
            stroke = getchar()
    sys.stdout.write("\n")
    sys.stdout.flush()
    return buf
