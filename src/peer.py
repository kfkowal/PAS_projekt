from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import concurrent.futures
import hashlib
import socket
import threading
import time
import pprint

class Peer:
    header_make_friend={
        'TYPE'      : "MAKE_FRIEND",
        'IP'        : None,
        'PORT'      : None 
    }

    header_end_connection={
        'TYPE' : "END_CONNECTION"
    }
    header_ok={
        'TYPE'      : 'OK'
    }
    header_not_ok={
        'TYPE' : 'NOT_OK'
    }
    header_key_exchange={
        'TYPE' : 'KEY_EXCHANGE',
        'KEY_LENGTH' : None
    }
    header_message={
        'TYPE' : 'MESSAGE',
        'MESSAGE_LENGTH' : None
    }
    header_join={
        'TYPE' : 'JOIN',
        'PORT' : None,
        'IP'   : None
    }
    header_announcement={
        'TYPE' : "ANNOUNCEMENT",
        'MESSAGE' : None,
        'KEY_LENGTH': None
    }
    header_list_announcement={
        'TYPE' : 'LIST'
    }
    header_get_public_key={
        'TYPE' : 'PUBLIC_KEY',
        'ID'  : None
    }
    header_route={
        'TYPE' : 'ROUTE',
        'FROM_PORT' : None,
        'TIME_TO_LIVE' : 5,
        'MESSAGE_LENGTH' : None
    }
    header_pong={
        'TYPE': 'PONG'
    }
    def __init__(self):
        self.main_private_key=self.__generate_private_key()
        self.secondary_private_key=self.__generate_small_private_key()
        self.friends={}
        self.index=0

        self.friendsLock = threading.Lock()
        self.friendsCheckLock = threading.Lock()
        self.routeCacheLock = threading.Lock()
        self.routeKeysLock =  threading.Lock()

        self.conversations={}
        self.conversationLock = threading.Lock()

        self.routeCache={}
        self.routeKeys=[]

        self.hash=None
        self.__set_addr()
        print(f"My port: {self.port} ############")
        self.__join()
        t1=threading.Thread(target=self.__listening, daemon=True)
        t1.start()
        try:
            while True:
                i=input(">: ")
                if i.strip()  == '':
                    pass
                elif i.split()[0].lower() == 'msg':
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(('127.0.0.1',self.friends[int(i.split()[1])][1]))
                    pub, priv=self.__key_exchange(s)
                    message=" ".join(i.split()[2:])
                    m=self.__message(s, pub, message)
                    self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), s)
                elif i.split()[0] == 'addf':
                    port=int(i.split()[1])
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(('127.0.0.1',port))
                    self.__make_friend(s,port,'127.0.0.1')
                elif i.split()[0] == 'sm':
                    try:
                        self.__send_secret_message(" ".join(i.split()[2:]),int(i.split()[1]))
                    except:
                        print("Cos poszlo nie tak, ponow probe")
                elif i.split()[0] =='ann':
                    self.__announcement(" ".join(i.split()[1:]))
                elif i =='list':
                    self.__list_announcements()
                elif i=='friends':
                    pprint.pprint(self.friends)
                elif i == 'history':
                    print('[ HISTORY ]')
                    for i in range(0,len(self.routeKeys)):
                        print(i,f" "+str(self.routeKeys[i][0]))
                elif i.split()[0] == 'resp':
                    try:
                        self.__send_response(' '.join(i.split()[2:]),int(i.split()[1]))
                    except:
                        print("Cos poszlo nie tak sprobuj ponownie")
                elif i== 'help':
                    print('[ HELP ]')
                    print('ann <tresc_ogloszenia> : aby oglosic swoje ogloszenie')
                    print('list : aby wylistowac wszystkie dostepne ogloszenia oraz odpowiadajace im indexy')
                    print('sm <indeks_ogloszenia> <tresc_wiadomosci> : wysyla sekretna wiadomosc do peera do ktorego nalezy ogloszenie o podanym indeksie')
                    print('history : aby wyswietlic wszystkie ostatnie odebrane  i wslane wiadomosci oraz ich indeksy')
                    print('resp <indeks_otrzymanej_wiadomosci_z_historii>  <tresc_odpowiedzi> : aby odpowiedziec na otrzymana wiadomosc')
                else:
                    print("nieznana instrukcja")
        except BaseException as e:
            print(f"ZATRZYMANOL: {e}")
        
    
    def __route(self, cyphered_message, header_to_send, client_socket, port):
        #print(f"MA BYC PORT: {port}")
        try:
            client_socket.connect(('127.0.0.1',int(port)))
            
            self.__send(
                self.__encode(
                    self.__dictionary_to_header(
                        header_to_send
                    )
                ), 
                client_socket
            )
            self.__send(cyphered_message, client_socket)
            self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), client_socket)
        except:
            self.friendsLock.acquire()
            k=None
            #print(f"Trzeba usunac: {int(port)}")
            for key, val in self.friends.items():
                #print(f"SSSSS: {val}")
                if val[1] == int(port):
                    k=key
            if k != None:
                self.friends.pop(k)
            else:
                pass
            self.friendsLock.release()
            self.__join()

    def __check_cache(self, cyphered_message): 
        self.routeCacheLock.acquire()
        hash = hashlib.sha256(cyphered_message).digest()
        tmp = self.routeCache.get(hash)
        if tmp == None:
            self.routeCache[hash] = 1
            self.routeCacheLock.release()
            return False
        else:
            self.routeCacheLock.release()
            return True

    def __try_decrypt(self, ciphered_message):
        message=None
        try:
            #print("probuje rozsz")
            message=self.__decrypt(ciphered_message, self.main_private_key)
            #print(f"UDALO SIE {message}")
        except:
            #print("niestety, ne udalo sie")
            message=None
        if message != None:
            return (message,self.main_private_key)
        
        tmp=None
        for private_key in self.routeKeys:
            try:
                message=self.__decrypt(ciphered_message, private_key[1])
                tmp=private_key[2]
            except:
                message=None
            if message!=None:
                return (message,tmp)
        return (None,None)

    def __add_route_key(self, last_message, my_key, key):
        self.routeKeysLock.acquire()
        airt=False
        tmp_bytes=self.__public_key_to_bytes(key)
        for _ in self.routeKeys:
            if self.__public_key_to_bytes(_[2]) == tmp_bytes:
                _[0] = last_message
                airt=True
                self.routeKeysLock.release()
                break

        if not airt:

            _=[]
            _.append(last_message)
            _.append(my_key)
            _.append(key)
            self.routeKeys.append(_)
            self.routeKeysLock.release()



    def __remove_route_key(self,key):
        self.routeKeysLock.acquire()
        tmp_bytes=self.__public_key_to_bytes(key)

        czy=False
        i=0
        for _ in self.routeKeys:
            if self.__public_key_to_bytes(_[2]) == tmp_bytes:
                czy=True
                break
            i+=1
        if czy:
            self.routeKeys.pop(i)
        self.routeKeysLock.release()



    def __handle_route(self, header_dictionary, client_socket):
        #print("HANDLING ROUTE")
        if int(header_dictionary['TIME_TO_LIVE']) >= 0:
            #print("TTL > 0, trza spr")
            cyphered_message=self.__recv(client_socket, length=int(header_dictionary['MESSAGE_LENGTH']))
            is_message_already_routed = self.__check_cache(cyphered_message)
            if is_message_already_routed:
                #print("Juz pyla routowana")
                pass
            else:
                message,my_key = self.__try_decrypt(cyphered_message)
                if message != None:
                    if len(message.split(b'|')) == 1:

                        self.__remove_route_key(my_key)
                        
                        print(f"TAJNA wiadomosc:[{str(message)}]")
                    elif len(message.split(b'|')) == 2:

                        key=message.split(b'|')[1]
                        message=message.split(b'|')[0]
                        self.__add_route_key(message, my_key, self.__bytes_to_public_key(key))
                        

                        print(f"TAJNA wiadomosc:[{str(message)}]")
                        #print(f"Klucz?: {tmp_key}")
                    else:
                        pass

                else:
                    #print("ROUTUJE DALEJ................")
                    port_to_avoid=header_dictionary['FROM_PORT']
                    header_dictionary['FROM_PORT']=self.port
                    header_dictionary['TIME_TO_LIVE']=int(header_dictionary['TIME_TO_LIVE'])-1
                    header_dictionary['MESSAGE_LENGTH']=len(cyphered_message)

                    threads=[]
                    for friend in list(self.friends.items()):
                        tmp=friend[1][1]

                        if int(tmp) != int(port_to_avoid):
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            t=threading.Thread(target=self.__route, args=[cyphered_message,header_dictionary, s, tmp], daemon=True)
                            threads.append(t)
                    for t in threads:
                        t.start()
        else:
            pass
            #print("TTL, nieodpowiednie")



    def __send_response(self, message, id):




        public_key = self.routeKeys[id][2]
        
        cyphered_message=self.__encrypt((message).encode('utf-8'),public_key)

        self.routeKeysLock.acquire()
        self.routeKeys[id][0]='You: '+str(message)
        self.routeKeysLock.release()
        self.__remove_route_key(public_key)
        header_dictionary=self.header_route
        header_dictionary['FROM_PORT']=self.port
        header_dictionary['MESSAGE_LENGTH']=len(cyphered_message)
        threads=[]
        for friend in list(self.friends.items()):
            tmp=friend[1][1]

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t=threading.Thread(target=self.__route, args=[cyphered_message,header_dictionary, s, tmp], daemon=True)
            threads.append(t)
        for t in threads:
            t.start()

    def __send_secret_message(self, message, id):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(('127.0.0.1',1769))

        header_to_send=self.header_get_public_key
        header_to_send['ID']=int(id)

        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send
                )
            ), 
            server
        )

        

        info_response_header=self.__recv(server)
        info_response_dictionary=self.__decode(info_response_header)
        info_response_dictionary=self.__parse_request_header(info_response_dictionary)

        if int(info_response_dictionary['STATUS']) == 200:
            public_key_length=info_response_dictionary['KEY_LENGTH']
            public_key= self.__recv(server, length=public_key_length)
            public_key=self.__bytes_to_public_key(public_key)


            self.__send(
                self.__encode(
                    self.__dictionary_to_header(
                        self.header_end_connection
                    )
                ), 
                server
            )
            server.close()

            route_key=self.__generate_small_private_key()
            self.__add_route_key('Me: '+str(message), route_key, public_key)
            my_public_key=self.__public_key_to_bytes(route_key.public_key())
            
            cyphered_message=self.__encrypt((message+"|").encode('utf-8')+my_public_key,public_key)
            header_dictionary=self.header_route
            header_dictionary['FROM_PORT']=self.port
            header_dictionary['MESSAGE_LENGTH']=len(cyphered_message)
            threads=[]
            for friend in list(self.friends.items()):
                tmp=friend[1][1]

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                t=threading.Thread(target=self.__route, args=[cyphered_message,header_dictionary, s, tmp], daemon=True)
                threads.append(t)
            for t in threads:
                t.start()


    def __list_announcements(self):
        header_to_send= self.header_list_announcement

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(('127.0.0.1',1769))
        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send
                )
            ), 
            server
        )
        info_response_header=self.__recv(server)
        info_response_dictionary=self.__decode(info_response_header)
        info_response_dictionary=self.__parse_request_header(info_response_dictionary)
        #print(f"ODEBRANE LISTA****** {info_response_dictionary}")
        list_a = info_response_dictionary['LIST'].split(',')
        self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), server)
        print("[ ANNOUNCEMENTS ]")
        for i in list_a:
            print(i)


    def __announcement(self, message):
        header_to_send= self.header_announcement
        header_to_send['MESSAGE'] = message
        header_to_send['KEY_LENGTH'] =len(self.__public_key_to_bytes(self.main_private_key.public_key()))
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(('127.0.0.1',1769))
        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send
                )
            ), 
            server
        )
        self.__send(self.__public_key_to_bytes(self.main_private_key.public_key()), server)
        self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), server)

    def __join(self):
        header_to_send = self.header_join
        header_to_send['PORT'] = self.port
        header_to_send['IP'] = '127.0.0.1'

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(('127.0.0.1',1769))
        self.__send(
                self.__encode(
                    self.__dictionary_to_header(
                        header_to_send
                    )
                ), 
                server
            )

        info_response_header=self.__recv(server)
        info_response_dictionary=self.__decode(info_response_header)
        info_response_dictionary=self.__parse_request_header(info_response_dictionary)

        self.hash = info_response_dictionary['HASH']

        self.__send(
                self.__encode(
                    self.__dictionary_to_header(
                        self.header_end_connection
                    )
                ), 
                server
            )
        #print(f"MOJ HASZ: {self.hash}")
        if int(info_response_dictionary['STATUS']) == 200:
            ports = info_response_dictionary['PORTS']
            ports = [int(port) for port in ports.split(',')]
            sockets = []
            for port in ports:
                #print(f"UWAGA, LACZE SIE Z : {port}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1',port))
                self.__make_friend(s,port,'127.0.0.1')


    def __check_if_friend_already_added(self,ip,port):
        for key, val in self.friends.items():
            if (ip,port) == val: return True
        return False

    def __handle_request_make_friend(self, header_dictionary, client_socket):
        port = int(header_dictionary['PORT'])
        ip=header_dictionary['IP']
        self.friendsCheckLock.acquire()
        if self.__check_if_friend_already_added(ip,port):
            self.__send(self.__encode(self.__dictionary_to_header(self.header_not_ok)), client_socket)
        else:
            self.__add_friend(port)
            self.__send(self.__encode(self.__dictionary_to_header(self.header_ok)), client_socket)
        self.friendsCheckLock.release()


    def __make_friend(self, client_socket, port, ip):
        self.friendsLock.acquire()
        if not self.__check_if_friend_already_added(ip, port):
            header_to_send = self.header_make_friend
            header_to_send['IP'] = self.ip
            header_to_send['PORT'] = self.port
            self.__send(
                self.__encode(
                    self.__dictionary_to_header(
                        header_to_send
                    )
                ), 
                client_socket
            )

            info_response_header=self.__recv(client_socket)
            info_response_dictionary=self.__decode(info_response_header)
            info_response_dictionary=self.__parse_request_header(info_response_dictionary)
            
            if info_response_dictionary['TYPE'] == 'NOT_OK':
                print("Nie mozna dodać do friends")
            elif info_response_dictionary['TYPE'] == 'OK':
                #print(f"UWAGA, PORT={port}")
                self.__add_friend(port=port)
        else:
            pass
        self.friendsLock.release()
        self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), client_socket)
        

    def __handle_request_message(self, header_dictionary, client_socket, private_key):
        message_length=int(header_dictionary['MESSAGE_LENGTH'])
        message_bytes=self.__recv(client_socket, length=message_length)
        message = self.__decrypt(message_bytes, private_key)
        message=self.__decode_message(message)
        print(f"Otrzymano wiadomosc: '{str(message)}'")
        
        
    
    def __message(self, client_socket, public_key, message):
        message=self.__encode(message)
        cipher=self.__encrypt(message, public_key)
        header_to_send=self.header_message
        header_to_send['MESSAGE_LENGTH'] = len(cipher)
        self.__send(self.__encode(self.__dictionary_to_header(header_to_send)), client_socket)
        self.__send(cipher, client_socket)




    def __handle_request_key_exchange(self,header_dictionary, client_socket):
        key_length = header_dictionary['KEY_LENGTH']
        #print(f"odbieram kluczp ubliczny o dlugosci: {key_length}")
        public_key_bytes = self.__recv(client_socket, length=key_length)
        #print("klucz odebrany hehehehee")
        public_key=self.__bytes_to_public_key(public_key_bytes)

        private_key=self.__generate_private_key()
        public_key_to_send=private_key.public_key()
        header_to_send=self.header_key_exchange
        header_to_send['KEY_LENGTH'] = len(self.__public_key_to_bytes(public_key_to_send))
        #print("Wysylam klucz")
        self.__send(self.__encode(self.__dictionary_to_header(header_to_send)), client_socket)
        self.__send(self.__public_key_to_bytes(public_key_to_send), client_socket)
        return (public_key,private_key)

    def __key_exchange(self,client_socket):
        private_key=self.__generate_private_key()
        public_key_to_send=private_key.public_key()
        header_to_send=self.header_key_exchange
        #print("Wysylam naglowek")
        header_to_send['KEY_LENGTH'] = len(self.__public_key_to_bytes(public_key_to_send))
        self.__send(self.__encode(self.__dictionary_to_header(header_to_send)), client_socket)
        #print("Wysylam klucz")
        self.__send(self.__public_key_to_bytes(public_key_to_send), client_socket)
        #print("klucz wyslany")
        request_header=self.__recv(client_socket)
        request_header=self.__decode(request_header)
        header_dictionary=self.__parse_request_header(request_header)
        key_length = header_dictionary['KEY_LENGTH']
        #print("odbieram kluczp ubliczny")
        public_key_bytes = self.__recv(client_socket, length=key_length)
        public_key=self.__bytes_to_public_key(public_key_bytes)

        return (public_key, private_key)

    def __handle_request(self,header_dictionary, client, public_key, private_key):
        #print(header_dictionary)
        if header_dictionary['TYPE'] == 'MAKE_FRIEND':
            self.__handle_request_make_friend(header_dictionary, client, public_key, private_key)
        elif header_dictionary['TYPE'] == 'MESSAGE' : 
            self.__handle_request_message(header_dictionary, client, private_key)
        elif header_dictionary['TYPE'] == 'ROUTE' : 
            self.__handle_route(header_dictionary,client)
        
    def __handle_ping(self,request_header, client_socket):
        print("pong")
        self.__send(self.__encode(self.__dictionary_to_header(self.header_pong)), client_socket)

    def __handle_connection(self, client_socket):
        public_key= None
        private_key=None
        while True:

            request_header=self.__recv(client_socket)
            request_header=self.__decode(request_header)
            request_header=self.__parse_request_header(request_header)

            if request_header['TYPE'] == 'END_CONNECTION':
                #print("Konce polaczenie")
                client_socket.close()
                break
            elif request_header['TYPE'] == 'KEY_EXCHANGE':
                public_key, private_key=self.__handle_request_key_exchange(request_header, client_socket)
            elif request_header['TYPE'] == 'MAKE_FRIEND':
                if int(request_header['PORT']) == self.port:
                    self.__send(self.__encode(self.__dictionary_to_header(self.header_end_connection)), client_socket)
                else:
                    self.__handle_request_make_friend(request_header, client_socket)
            elif request_header['TYPE'] == 'PING':
                self.__handle_ping(request_header, client_socket)
            else:
                #print("nie Konce polaczenie")
                self.__handle_request(request_header, client_socket, public_key, private_key)


    def __listening(self):
        print("rozpoczynam nasluchiwanie")
        while True:
            client, addr= self.sock.accept()
            #print(f"polaczono: {client}:{addr}")
            handle_connection_thread = threading.Thread(target=self.__handle_connection, args=[client], daemon=True)
            handle_connection_thread.start()


    def __add_friend(self,port,ip='127.0.0.1'):
        self.friends[self.index] = (ip,port)
        self.index+=1


    def __send(self, bajty, client):
        client.sendall(bajty)

    def __recv(self, client, length=None):
        if length==None:
            data = b''
            while b'\r\n\r\n' not in data:
                data += client.recv(1)
            return data
        else:
            data = b''
            licznik=0
            #print(f"do pobrania: {int(length)}")
            while len(data) < int(length):
                data+= client.recv(1)
            #print("k pobrane")
            return data


    def __get_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        return s

    def __dictionary_to_header(self, dictionary):
        data=''
        for key, val in dictionary.items():
            data+=f'{key.upper()}: {str(val).upper()}\r\n'
        data+='\r\n'
        return data

    def __decode(self, byte_data):
        return byte_data.decode('utf-8')[:-4]
    def __decode_message(self, byte_data):
        return byte_data.decode('utf-8')

    def __encode(self, string_data):
        return string_data.encode('utf-8')

    def __parse_request_header(self, string_req):
        
        string_req=string_req.split('\r\n')
        #print(string_req)
        req_dct={}
        for key_val in string_req:
            tmp=key_val.split(':')
            req_dct[tmp[0].strip()]=tmp[1].strip()
        return req_dct



    def __set_addr(self):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        self.sock.bind(("localhost",0 ))
        self.sock.listen( 10 )
        self.ip, self.port = self.sock.getsockname()
        

    def __generate_private_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        return private_key

    def __generate_small_private_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        return private_key

    def __private_key_to_bytes(self, key):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    def __bytes_to_private_key(self, pem_bytes):
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
        )
        return private_key



    def __public_key_to_bytes(self, public_key):
        ssh = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return  ssh

    def __bytes_to_public_key(self, ssh_bytes):
        public_key= serialization.load_pem_public_key(
            ssh_bytes
            )
        return public_key
        




    def __encrypt(self, message_bytes, public_key):
        #message_bytes=message_string.encode('utf-8')
        ciphertext = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def __decrypt(self, cipher_bytes, private_key):
        plaintext = private_key.decrypt(
            cipher_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

p=Peer()
