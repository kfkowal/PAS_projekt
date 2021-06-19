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
import hashlib
import random

class Peer:
    header_ok={
        'TYPE'      : 'OK'
    }
    header_not_ok={
        'TYPE' : 'NOT_OK'
    }

    header_node={
        'TYPE' : 'NODES',
        'STATUS' : None,
        'IPS' : None,
        'PORTS' : None,
        'HASH'  : None
    }
    header_list={
        'TYPE' : 'LIST',
        'LIST' :None
    }
    header_public_key={
        'TYPE' : 'PUBLIC_KEY',
        'STATUS' : None,
        'KEY_LENGTH'  : None
    }
    header_ping={
        'TYPE' : 'PING'
    }
    header_end_connection={
        'TYPE' : "END_CONNECTION"
    }
    def __init__(self):

        self.__set_addr()
        print(f"SERVER port: {self.port} ############")
        self.peerLock = threading.Lock()
        self.announcementLock = threading.Lock()
        self.peers={}
        self.index=random.randint(0,1000)

        self.announcements = {}
        self.announcementId=0

        t1=threading.Thread(target=self.__listening, daemon=True)
        ping_peers_thread = threading.Thread(target=self.__ping_peers,  daemon=True)
        
        t1.start()
        #ping_peers_thread.start()
        try:
            while True:
                i = input("$>: ")
        except:
            print("Zatrzymano serwer")

    def __handle_public_key(self,header_dictionary,  client_socket):
        header_to_send=self.header_public_key
        tmp = self.announcements.get(int(header_dictionary['ID']))
        if tmp == None:
            header_to_send['STATUS'] = 406
        else:
            header_to_send['STATUS'] = 200
            header_to_send['KEY_LENGTH'] = len(self.announcements[int(header_dictionary['ID'])][1])

        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send)), client_socket)
        self.__send(self.announcements[int(header_dictionary['ID'])][1], client_socket)

    def __handle_announcement(self, header_dictionary, client_socket):
        message = header_dictionary['MESSAGE'] 
        len=header_dictionary['KEY_LENGTH'] 
        
        public_key = self.__recv(client_socket,length=len)
        

        self.announcementLock.acquire()
        self.announcements[self.announcementId] = (message, public_key)
        self.announcementId+=1
        self.announcementLock.release()

        # for i in list(self.announcements.items()):
        #     print(i[1][0])

    def __handle_list(self, client_socket):
        header_to_send= self.header_list
        tmp_list=[]
        for i in list(self.announcements.items()):
            tmp = str(i[0])+". "+str(i[1][0])
            tmp_list.append(tmp)

        header_to_send['LIST']=",".join(tmp_list)
        #print(f"ODSYLAM:: {header_to_send['LIST']}")
        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send)), client_socket)

    def __get_random_peers(self,hash, port, ip='127.0.0.1'):
        self.peerLock.acquire()
        tmp_list=list(self.peers.items())
        self.peers[hash]=(port,ip)
        return_list=[]
        if len(tmp_list) == 0:
            return_list= []
        elif len(tmp_list) == 1:
            return_list= [tmp_list[0][1]]
        elif len(tmp_list) == 2:
            return_list= [tmp_list[0][1],tmp_list[1][1]]
        else:
            last=None
            while len(return_list) < 2:
                tmp=random.choice(tmp_list)
                spr=True
                for t in return_list:
                    #print(f"A TERAZ POROWNAM {t} do {tmp}")
                    if t[0] == tmp[1][0]:
                        spr=False
                if spr:   
                    return_list.append(tmp[1])

        self.peerLock.release()
        #print(f"RETURNED LIST: {return_list}")
        return return_list

    def __handle_join(self,header_dictionary, client_socket, public_key, private_key):
        h= hashlib.sha256(bytes(self.index)).digest()
        self.index+=1
        peer_list = self.__get_random_peers(h, int(header_dictionary['PORT']))
        ports=''
        ips=''

        for index in range(len(peer_list)):
            ports+= str(peer_list[index][0])
            ips  += peer_list[index][1]

            if peer_list[index] != peer_list[-1]:
                ports+=','
                ips+=','
        #(f"PEERY CSV: {ports}")
        header_to_send=self.header_node
        if len(peer_list) == 0:
            header_to_send['STATUS'] = 405
        else:
            header_to_send['STATUS'] = 200
            header_to_send['PORTS'] = ports
            header_to_send['IPS'] = ips
        header_to_send['HASH']=h
        self.__send(
            self.__encode(
                self.__dictionary_to_header(
                    header_to_send)), client_socket)
        
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
            elif request_header['TYPE'] == 'JOIN':
                self.__handle_join(request_header, client_socket, None, None)
            elif request_header['TYPE'] == 'ANNOUNCEMENT':
                self.__handle_announcement(request_header, client_socket)
            elif request_header['TYPE'] == 'LIST':
                self.__handle_list(client_socket)
            elif request_header['TYPE'] == 'PUBLIC_KEY':
                self.__handle_public_key(request_header, client_socket)
            else:
                #print("nie Konce polaczenie")
                self.__handle_request(request_header, client_socket, public_key, private_key)


    def __ping_peer(self, key_port_ip):
        #print(f"bede sie laczyl z {ip_port}")
        key=key_port_ip[0]
        port_ip=key_port_ip[1]
        try:
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer.connect((port_ip[1],port_ip[0]))
            self.__send(
                    self.__encode(
                        self.__dictionary_to_header(
                            self.header_ping
                        )
                    ), 
                    peer
                )
            response=self.__recv(peer)
            self.__send(
                    self.__encode(
                        self.__dictionary_to_header(
                            self.header_end_connction
                        )
                    ), 
                    peer
                )
            peer.close()
            print(f"---ILOSC PEROWL {len(self.peers.values())}")
        except:

            self.peerLock.acquire()
            tmp_list=self.peers.pop(key)
            self.peerLock.release()
            print(f"ILOSC PEROW: {len(self.peers.values())}")

    def __ping_peers(self):
        #print("pingp eers")
        while True:
            time.sleep(5)
            #print("pinguje")
            self.peerLock.acquire()
            tmp_list=self.peers.items()
            self.peerLock.release()
            threads=[]
            for el in tmp_list:
                t=threading.Thread(target=self.__ping_peer, args=[el], daemon=True)
                threads.append(t)
            for t in threads:
                t.start()
            for t in threads:
                t.join()


        
    def __listening(self):
        print("rozpoczynam nasluchiwanie")
        while True:
            client, addr= self.sock.accept()
            #print(f"polaczono: {client}:{addr}")
            handle_connection_thread = threading.Thread(target=self.__handle_connection, args=[client], daemon=True)
            
            

            handle_connection_thread.start()
            



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
        self.sock.bind(("localhost", 1769))
        self.sock.listen( 10 )
        self.ip, self.port = self.sock.getsockname()
        


p=Peer()
