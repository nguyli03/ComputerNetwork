#!/usr/bin/env python3
#encoding: UTF-8

from socket import *
from random import randint

HOST = "localhost"
PORT = 43053
q_type_dict = {"A": 1, "AAAA": 28}

class DNSServer:
    def __init__(self):
        self.msg_qry = bytearray()
        self.dataDictM=[]
        self.query={}
    def readHost(self,filename):
        file=open(filename)
        origin=file.readline().split()[1]
        ttlDefault=file.readline().split()[1]
        line=file.readline()
        dataDictM={}
        while line!='':
            data=line.split()
            if data[0]=='IN' or data[1]=='IN':
                if data[0]=='IN':
                    dataDictM[key]['ttl'].append(ttlDefault)
                    dataDictM[key]['class']=data[0]
                    dataDictM[key]['type'].append(data[1])
                    dataDictM[key]['address'].append(data[2])            
                elif data[0][0] in '0123456789':
                    dataDictM[key]['ttl'].append(data[0])
                    dataDictM[key]['class']=data[1]
                    dataDictM[key]['type'].append(data[2])
                    dataDictM[key]['address'].append(data[3])
                elif ord(data[0][0]) in range(65,122):
                    dataDictM[data[0]]={}
                    dataDictM[data[0]]['ttl']=[ttlDefault]
                    dataDictM[data[0]]['class']=data[1]
                    dataDictM[data[0]]['type']=[data[2]]
                    dataDictM[data[0]]['address']=[data[3]]         
            else:
                dataDictM[data[0]]={}
                dataDictM[data[0]]['ttl']=[data[1]]
                dataDictM[data[0]]['class']=data[2]
                dataDictM[data[0]]['type']=[data[3]]
                dataDictM[data[0]]['address']=[data[4]]
                key=data[0]
            line=file.readline()
        print(dataDictM['kyle'])
        self.dataDictM=dataDictM
    def format_returnQry(self, msg_qry,answer):
        trans_id = self.query['trans_id']
        flags = 0x8180
        questions = self.query['questions']
        rr_ans = self.query['rr_ans']
        rr_auth = self.query['rr_auth']
        rr_add = self.query['rr_add']

        self.msg_qry.append((trans_id & 0xff00) >> 8)
        self.msg_qry.append(trans_id & 0x00ff)
        self.msg_qry.append((flags & 0xff00) >> 8)
        self.msg_qry.append(flags & 0x00ff)
        self.msg_qry.append((questions & 0xff00) >> 8)
        self.msg_qry.append(questions & 0x00ff)
        self.msg_qry.append((rr_ans[0] & 0xff00) >> 8)
        self.msg_qry.append(rr_ans[1] & 0x00ff)
        self.msg_qry.append((rr_auth & 0xff00) >> 8)
        self.msg_qry.append(rr_auth & 0x00ff)
        self.msg_qry.append((rr_add & 0xff00) >> 8)
        self.msg_qry.append(rr_add & 0x00ff)
        #append the query again:
        d=12
        while d <len(msg_qry):
            self.msg_qry.append(msg_qry[d])
            d+=1
            
        i=0 
        while i<rr_ans[1]:
            self.msg_qry.append((0xc00c & 0xff00)>>8)
            self.msg_qry.append(0xc00c & 0x00ff)
            if answer['type'][i]=='A':
                qtype=1
                ip=4
            if answer['type'][i]=='AAAA':
                qtype=28
                ip=16
                
            self.msg_qry.append((qtype & 0xff00) >> 8)
            self.msg_qry.append(qtype & 0x00ff)
            self.msg_qry.append((self.query['qry_clss'] & 0xff00) >> 8)
            self.msg_qry.append(self.query['qry_clss'] & 0x00ff)
            #append ttl:
            self.msg_qry.append((answer['ttl'][i]&0xff000000)>>12)
            self.msg_qry.append((answer['ttl'][i]&0x00ff0000)>>8)
            self.msg_qry.append((answer['ttl'][i]&0x0000ff00)>>4)
            self.msg_qry.append((answer['ttl'][i]&0x000000ff))
            #append ipv4:
            if qtype==1:
                #append data length
                self.msg_qry.append((ip&0xff00)>>8)
                self.msg_qry.append(ip&0x00ff)                
                ip=answer['address'][i].split('.')
                for e in ip:
                    self.msg_qry.append(int(e))
            #append ipv6:
            if qtype==28:
                #append data length
                self.msg_qry.append((ip&0xff00)>>8)
                self.msg_qry.append(ip&0x00ff)                            
                ip=answer['address'][i].split(':')
                print(ip)
                for e in ip:
                    self.msg_qry.append(int(e[0:2],16))
                    self.msg_qry.append(int(e[2:],16))
            i+=1
        print (self.msg_qry)
        return self.msg_qry
    #parse through the query to see the response    
    def parse_qry(self, msg_qry):
        i = 0 # transaction id
        self.query['trans_id'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 2 # flags
        self.query['flags'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 4 # questions
        self.query['questions'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 6 # answers
        self.query['rr_ans'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 8 # authority rrs
        self.query['rr_auth'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 10 # additional rr
        self.query['rr_add'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = 12 # start of the query
        self.query['domain'] = []
        while msg_qry[i] != 0:
            dom_len = msg_qry[i]
            self.query['domain'].append(msg_qry[i+1:i+dom_len+1])
            i = i + dom_len + 1
        self.query['name']=self.query['domain'][0].decode()
        print(self.query['name'])
        i = i + 1 # type
        self.query['qry_type'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        i = i + 2 # class
        self.query['qry_clss'] = self.bytes_to_val([msg_qry[i], msg_qry[i+1]])
        if self.query['qry_clss'] != 1:
            raise Exception("Unknown class")
        answer_start = i + 2
        return self.parse_DNS_query(msg_qry)
    
    # parse DNS server query
    def parse_DNS_query(self,msg_qry):
        answer={}
        answer['type']=[]
        answer['address']=[]
        answer['ttl']=[]
        ttl=[]
        if self.query['name'] in self.dataDictM:
            name=self.query['name']
            print(self.query['qry_type'])
            qtype=self.query['qry_type']
            if qtype==1:
                qtypeStr='A'
            if qtype==28:
                qtypeStr='AAAA'
            if qtypeStr in self.dataDictM[name]['type']:
                answer['name']=name
                #print('something')
                i=0
                while i <len(self.dataDictM[name]['type']): 
                    if self.dataDictM[name]['type'][i] == qtypeStr:
                        answer['type'].append(self.dataDictM[name]['type'][i])
                        answer['address'].append(self.dataDictM[name]['address'][i])
                        ttl.append(self.dataDictM[name]['ttl'][i])
                    i+=1
                    answer['rr_ans']=len(self.dataDictM[name]['type'])
            else:
                return ("This domain does not have this query type")
        else:
            return ("This domain does not exist")
        self.query['rr_ans']=self.val_to_n_bytes(len(answer['address']),2)
        print(ttl)
        for i in range(0,len(ttl)):
            answer['ttl'].append(self.convertTTL(ttl[i]))
        print(answer)
        return self.format_returnQry(msg_qry,answer)
    
    def convertTTL(self,ttl):
        if ttl=='1s':
            return 1
        if ttl=='1m':
            return 60
        if ttl=='1h':
            return 3600
        if ttl=='1d':
            return 86400
        if ttl=='1w':
            return 604800
        #assume a year has 365 days
        if ttl=='1y':
            return 31536000

    def resolve(self):
        server_sckt = socket(AF_INET, SOCK_DGRAM)
        server_sckt.bind((HOST, PORT))
        print("Listening on %s:%d" % (HOST, PORT))
        while True:
            (msg_qry, client_addr) = server_sckt.recvfrom(2048)
            self.msg_qry = bytearray()            
            response=self.parse_qry(msg_qry)
            server_sckt.sendto(response, client_addr)
        print("Stopping the server")
        server_sckt.close()
           
        return self.parse_qry(msg_qry)
    # Split a value into 2 bytes
    def val_to_2_bytes(self, value):
        byte_1 = (value & 0xff00) >> 8
        byte_2 = value & 0x00ff
            
        return [byte_1, byte_2]
    # Split a value into 2 bytes
    def val_to_n_bytes(self, value, n_bytes):
        result = []
        for s in range(n_bytes):
            byte = (value & (0xff << (8 * s))) >> (8 * s)
            result.insert(0, byte)
            
        return result
    # Merge 2 bytes into a value
    def bytes_to_val(self, bytes_lst):
        value = 0
        for b in bytes_lst:
            value = (value << 8) + b
            
        return value
    # Extract first two bits of a two-byte sequence
    def get_2_bits(self, bytes):
        return bytes[0] >> 6
    # Extract size of the offset from a two-byte sequence
    def get_offset(self, bytes):
        return ((bytes[0] & 0x3f) << 8) + bytes[1]    
def main():
    server=DNSServer()
    sever=server.readHost('hosts.txt')
    print(server.resolve())
if __name__=="__main__":
    main()