#!/usr/bin/env python3
VERSION="3.0 hotfix 2"
import sys
if sys.version_info[0] != 3:
    exit("Must be run with python3!")
from netifaces import interfaces,ifaddresses,AF_INET
import itertools
import json
import os
import socket
from threading import Thread
import tkinter
import easyinquirer
import encryptionsuite
import datetime

DEBUG = True

def debug(string):
    if debug:
        print("[DEBUG] {}".format(string))

tobytes = encryptionsuite.tobytes
tostring = encryptionsuite.tostring

def spawnchat(clisock,username,AESKEY):
    def receive():
        msg_list.insert(tkinter.END,"Conversation started at {}".format(datetime.datetime.now().strftime("%d %h %Y %H:%M:%S")))
        muted = False
        while True:
            
            try:
                msg = clisock.recv(BUFSIZ)
                realmessage = False
                msg = encryptionsuite.decrypt_aes(msg,AESKEY)
                if "{quit}" in msg[:6]:
                    msg = "<{} has left the chat>".format(username)
                
                elif "{attach}" in msg[:8]:
                    msg = "<{} would like to share a file (ERR2-ATCH)>".format(username)

                else:
                    msg = "[{}] {}".format(username,msg)
                    realmessage = True
                    while len(msg) > 70:
                        bit = msg[:70]
                        msg_list.insert(tkinter.END,bit)
                        msg = msg[70:]

                try:
                    msg_list.insert(tkinter.END, msg)
                    
                #    if realmessage and not top.focus_displayof() and not muted:
                        #chime()
                except:
                    exit() #Assume this error is because chat died.
                msg_list.yview("end")
            except OSError:  # Possibly client has left the chat.
                clisock.close()
                top.quit()
                top.destroy()
                exit()
                break
            except:
                clisock.close()
                top.quit()
                top.destroy()
                exit()
                break
                
    def send(event=None):  # event is passed by binders.
        msg = my_msg.get()
        my_msg.set("")  # Clears input field.
        outmsg = encryptionsuite.encrypt_aes(msg,AESKEY)
        clisock.send(outmsg)
        
        msg = "you> {}".format(msg)
        try:
            while len(msg) > 70:
                bit = msg[:70]
                msg_list.insert(tkinter.END,bit)
                msg = msg[70:]
            msg_list.insert(tkinter.END,msg)
        except:
            exit() #Assume chat died
        msg_list.yview("end")  
        
        if msg == "{quit}":
            clisock.close()
            top.quit()
            top.destroy()
            exit()

    def clear(event=None):
        msg_list.delete(0,'end')
        msg_list.yview("end")

    def on_closing(event=None):
        my_msg.set("{quit}")
        send()
        top.quit()
        top.destroy()
        exit()

    top = tkinter.Tk()
    top.title("Spectre | {}".format(username))

    messages_frame = tkinter.Frame(top)
    my_msg = tkinter.StringVar()  # For the messages to be sent.
    scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
    # Following will contain the messages.
                                                    #15,50
    msg_list = tkinter.Listbox(messages_frame, height=18, width=65, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
    msg_list.pack()
    messages_frame.pack()

    entry_field = tkinter.Entry(top, textvariable=my_msg,width=50)
    entry_field.bind("<Return>", send)
    entry_field.pack(side=tkinter.LEFT)

    send_button = tkinter.Button(top, text="Send", command=send)
    send_button.pack(side=tkinter.LEFT)

    clear_button = tkinter.Button(top,text="Clear",command=clear,width=3,height=1)
    clear_button.pack(side=tkinter.RIGHT)
    
    top.resizable(False,False)
     
    top.protocol("WM_DELETE_WINDOW", on_closing)

    BUFSIZ = 2048
    
    receive_thread = Thread(target=receive)
    receive_thread.start()
    tkinter.mainloop()  # Starts GUI execution.

#END GUI
#To invoke, run
#spawnchat(socket,username,aeskey)
#Only run once all the behind-the-scenes key exchange voodoo is donei
"""
Client					Server
Connect
					Send RSA key
Gen AES key
Encrypt AES key w/ server RSA key
Send encrypted AES key

Establish encrypted channel		Establish encrypted channel ; ALL DATA FROM HERE ON OUT IS ENCRYPTED WITH AES
					Send username+PKHash
Send username+PKHash
"""
def get_ips():
    links = filter(None, (ifaddresses(x).get(AF_INET) for x in interfaces()))
    links = itertools.chain(*links)
    ip_addresses = [x['addr'] for x in links]
    return ip_addresses

class cui_recv(Thread):
    def __init__(self,username,sock):
        Thread.__init__(self)
        self.sock = sock

        self.start()

    def run(self):
        while True:
            data = self.sock.recv(2048)
            dec = encryptionsuite.decrypt_aes(data,aeskey)
            if dec:
                print("[{}] {}".format(username,dec))

def guiless(s,username,aeskey):
    print("GUILESS ENVIRONMENT DETECTED\nENTERING FALLBACK MODE\nWARNING: EXPECT A DEGRADED USER EXPERIENCE\n")
    print("Spectre | {}".format(username))
    print("Conversation started at {}".format(datetime.datetime.now().strftime("%d %h %Y %H:%M:%S")))
    cui_recv(username,s)
    while True:
        text = raw_input("")
        s.send(encrypt_aes(text,aeskey))

def client(username,password,uid,pubkey,privkey):
    host = easyinquirer.ask("Please enter the server IP")
    port = easyinquirer.ask("Please enter the server port (default 2143)")
    if not host:
        print("Error: invalid selection.")
        client(username,password,uid,pubkey,privkey)
        exit()

    if not port:
        port = 2143
    else:
        try:
            port = int(port)
            if port > 65535 or port < 1:
                port = 2143
        except:
            port = 2143
    s = socket.socket()
    s.connect((host,port))
    serverrsakey = s.recv(4096*2)
    serverrsakey = tostring(serverrsakey)
    aeskey = encryptionsuite.gen_key_aes()
    rsadaeskey = encryptionsuite.encrypt_rsa(aeskey,serverrsakey)
    s.send(rsadaeskey)
    if "CHANNEL HANDSHAKE" not in tostring(encryptionsuite.decrypt_aes(s.recv(256),aeskey)):
        raise RuntimeError("ERR1-AKEY: Secure channel handshake failed")
    s.send(encryptionsuite.encrypt_aes("CHANNEL HANDSHAKE OKAY",aeskey))

    serverid = encryptionsuite.decrypt_aes(s.recv(256),aeskey)
    serverusername = serverid.split(":")[0]
    serveruid = serverid.split(":")[1]
    checkhash = str(encryptionsuite.sha256(serverrsakey))
    if str(serveruid) != checkhash:
        print("CRITICAL - ERR1-UIDM - RSA identity mismatch")
        print("[!] WARNING: RSA key does not match reported RSA fingerprint. This could be a sign of man-in-the-middle, impersonation, or other nefarious activity!")
        print("The only reason to provide a mismatched UID is because the sender does not have access to the real keypair the UID corresponds to.")
        print("EXPECTED FINGERPRINT: {} (UID)".format(serveruid))
        print("ACTUAL FINGERPRINT:   {} (PUBLIC KEY HASH)".format(checkhash))
        exit("\nTerminating connection")
        s.close()

    #TODO: contact check

    identifier = username + ":" + uid

    s.send(encryptionsuite.encrypt_aes(identifier,aeskey))
    
    try:
        spawnchat(s,serverusername,aeskey)
    except:
        guiless(s,serverusername,aeskey)

def server(username,password,uid,pubkey,privkey):
    s = socket.socket()
    ips = ["0.0.0.0"]
    ips += get_ips()
    ips.remove("127.0.0.1")
    ips.append("127.0.0.1")
    host = easyinquirer.list("Please select the desired server IP address\n0.0.0.0 is recommended, 127.0.0.1 is not.",ips)
    port = easyinquirer.ask("Please enter a port number to listen on (default is 2143)\nPort: ")
    if not port:
        port = 2143
    else:
        try:
            port = int(port)
            if port > 65535 or port < 1:
                port = 2143
        except:
            port = 2143
    s = socket.socket()
    try:
        s.bind((host,port))
        print("Listening on IP {}, PORT {}\nThese are the settings needed to connect to you\n\nAwaiting client...".format(host,port))
    except:
        print("ERR0-SOCK: Generic socket error. This port may be in use.")
        server(username,password,uid,pubkey,privkey)
        exit()

    s.listen(5)
    sock,a = s.accept()
    print("Got connection")
    sock.send(tobytes(pubkey))
    rsadaeskey = sock.recv(1024)
    aeskey = encryptionsuite.decrypt_rsa(rsadaeskey,privkey,password)
    sock.send(encryptionsuite.encrypt_aes("CHANNEL HANDSHAKE",aeskey))
    handshake = encryptionsuite.decrypt_aes(sock.recv(256),aeskey)
    if 'CHANNEL HANDSHAKE OKAY' not in tostring(handshake):
        raise RuntimeError("ERR1-AKEY: Secure channel handshake failed")
    identifier = username + ":" + uid
    sock.send(encryptionsuite.encrypt_aes(identifier,aeskey))
    
    try:
        otheruser = encryptionsuite.decrypt_aes(sock.recv(1024),aeskey)
    
        otherusername = otheruser.split(":")[0]
        otheruseruid = otheruser.split(":")[1]
    except:
        exit()
    
    #TODO: Add contact check here, but do that later. 

    try:
        spawnchat(sock,otherusername,aeskey)
    except:
        guiless(sock,otherusername,aeskey)

def authenticated(username,password,uid,pubkey,privkey):
    mode = easyinquirer.list("Would you like to operate in Client or Server mode?",['Client','Server'])
    if mode == 'Client':
        print("Client mode selected")
        client(username,password,uid,pubkey,privkey)
    elif mode == 'Server':
        print("Server mode selected")
        server(username,password,uid,pubkey,privkey)

def newuser(usernames):
    disallowed = ["|","{","}","(",")"," ",".",",",";",":"]
    if not usernames:
        usernames = []
    while True:
        fail = False
        user = easyinquirer.ask('Enter desired username:')
        if user not in usernames and user.isalpha() and "create" not in user.strip(" ").lower() and len(user) <= 16:
            for c in disallowed:
                if c in user:
                    print("Username contains illegal character: {}".format(c))
                    fail = True
        else:
            print("Username disallowed")

        if not fail:
            print("Username is available")
            break
    while True:
        password = easyinquirer.password('Enter desired password:')
        if password == easyinquirer.password("Confirm password:"):
            break
        else:
            print("Error - passwords do not match.")
    print("Password saved. Creating login file.")
    pub,priv = encryptionsuite.gen_key_rsa(password)
    pub = tostring(pub)
    priv = tostring(priv)
    passhash = encryptionsuite.sha256withsalt(password)
    uid = encryptionsuite.sha256(pub)
    

    f = open("users/{}.slf3".format(user),"w")
    data = json.dumps({'username':user,'hash':str(passhash),'uid':str(uid),'publickey':str(pub),'encryptedprivkey':str(priv)})
    f.write(data)
    f.close()
    
    print("Your login file is now complete. You may now login.")
    login()

def login(username=None,password=None):
    usernames = []
    userfiles = os.listdir('users')
    for user in userfiles:
        if user[-len(".slf3"):] == ".slf3":
            usernames.append(user[:-len(".slf3")])
    if usernames == []:
        print("No users found. Creating new user")
        newuser([])
    
    usernames.append("Create new user")
    usernames.append("Exit Spectre")
    user = easyinquirer.list("Please select your user, or create a new one",usernames)

    if user == "Create new user":
        newuser(usernames)
    elif user == "Exit Spectre":
        exit("Goodbye")

    else:
        authd = False
        #password = easyinquirer.password("Enter your password: ")
        f = open("users/{}.slf3".format(user),"r") 
        data = f.read()
        f.close()
        jsondata = json.loads(data)
        if user != jsondata['username']:
            user = jsondata['username']
        if True: #Cheeky indenting
            tries = 0
            while tries < 3:
                password = easyinquirer.password("Enter your password: ")
                if encryptionsuite.verifysha256(jsondata['hash'],password):
                    authd = True
                    break
                else:
                    print("Password incorrect")
                tries += 1 
        if authd:
            print("Welcome, {}".format(user))
            pubkey = jsondata['publickey']
            uid = jsondata['uid']
            privkey = jsondata['encryptedprivkey']
            authenticated(user,password,uid,pubkey,privkey)
        else:
            exit("Authentication failed.")
            
print("Welcome to Spectre")
print("Current version: {}".format(VERSION))
login()

#ONLY CALL WHEN READY TO TALK
#spawnchat(socket,'rootabeta','AESKEYHERE')
