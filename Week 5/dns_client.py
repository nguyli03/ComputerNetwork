#!/usr/bin/env python3
#encoding: UTF-8

from socket import *
from random import randint

PORT = 43053
q_type_dict = {"A": 1, "AAAA": 28}

class DNSClient:
    def __init__(self):
        self.msg_qry = bytearray()
    
    def format_query(self, query_domain, query_type):
        trans_id = randint(0, 65535)
        flags = 0x100 #0x0100 # default
        questions = 1
        rr_ans =0
        rr_auth = 0
        rr_add = 0
        q_name = query_domain # human-readable
        q_name_lst = q_name.split('.')
        try:
            q_type = q_type_dict[query_type]
        except:
            raise Exception("Unknown query type")
        q_class = 1 # IN
        
        self.msg_qry.append((trans_id & 0xff00) >> 8)
        self.msg_qry.append(trans_id & 0x00ff)
        self.msg_qry.append((flags & 0xff00) >> 8)
        self.msg_qry.append(flags & 0x00ff)
        self.msg_qry.append((questions & 0xff00) >> 8)
        self.msg_qry.append(questions & 0x00ff)
        self.msg_qry.append((rr_ans & 0xff00) >> 8)
        self.msg_qry.append(rr_ans & 0x00ff)
        self.msg_qry.append((rr_auth & 0xff00) >> 8)
        self.msg_qry.append(rr_auth & 0x00ff)
        self.msg_qry.append((rr_add & 0xff00) >> 8)
        self.msg_qry.append(rr_add & 0x00ff)
        for d in q_name_lst:
            self.msg_qry.append(len(d))
            for c in d:
                self.msg_qry.append(ord(c))
        self.msg_qry.append(0)
        self.msg_qry.append((q_type & 0xff00) >> 8)
        self.msg_qry.append(q_type & 0x00ff)
        self.msg_qry.append((q_class & 0xff00) >> 8)
        self.msg_qry.append(q_class & 0x00ff)
    
    def parse_response(self, msg_resp):
        i = 0 # transaction id
        trans_id = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        i = 2 # flags
        flags = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        if (flags >> 15) == 1:
            print("Response received")
        i = 4 # questions
        questions = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        i = 6 # answers
        rr_ans = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        print("Answers: %d" % rr_ans)
        i = 8 # authority rrs
        rr_auth = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        i = 10 # additional rr
        rr_add = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        i = 12 # start of the query
        domain = []
        while msg_resp[i] != 0:
            dom_len = msg_resp[i]
            domain.append(msg_resp[i+1:i+dom_len+1])
            i = i + dom_len + 1
        i = i + 1 # type
        qry_type = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        i = i + 2 # class
        qry_clss = self.bytes_to_val([msg_resp[i], msg_resp[i+1]])
        if qry_clss != 1:
            raise Exception("Unknown class")
        answer_start = i + 2
        return self.parse_answers(msg_resp, answer_start, rr_ans)
    # extract IPv4 address
    def parse_address_a(self, addr_len, addr_bytes):
        resp_addr = []
        # put bytes into a list
        for i in range(addr_len):
            resp_addr.append(addr_bytes[i])
        resp_addr = '.'.join(str(x) for x in resp_addr)

        return resp_addr
    # extract IPv6 address
    def parse_address_aaaa(self, addr_len, addr_bytes):
        resp_addr = []
        # put bytes into a list
        for i in range(0, addr_len, 2):
            resp_addr.append((addr_bytes[i] << 8) + addr_bytes[i+1])
        resp_addr = ':'.join(str(hex(x)) for x in resp_addr)

        return resp_addr.replace('0x', '')
    # parse DNS server answers
    def parse_answers(self, msg_resp, offset, rr_ans):
        answers = []
        for _ in range(rr_ans):
        #for _ in range(1): # get 1 answer and quit
            i = 0 # label at teh start of the answer
            if (msg_resp[offset+i] >> 6) == 0b11: # first two bits of the answer should be 11
                dom_start = self.bytes_to_val([msg_resp[offset+i], msg_resp[offset+i+1]])
                dom_start = dom_start & 0x3fff ## extract last 14 bits and convert tham to a decimal value
            else:
                raise Exception("Answer does not have a label pointer")
            domain = []
            i = dom_start
            while msg_resp[i] != 0:
                dom_len = msg_resp[i]
                domain.append(msg_resp[i+1:i+dom_len+1].decode())
                i = i + dom_len + 1
            domain = '.'.join(domain)
            i = 2 # jump to type
            resp_type = self.bytes_to_val(msg_resp[offset+i:offset+i+2])
            if resp_type not in [1, 28]:
                raise Exception("Unknown address type")
            i = i + 2 # jump to class
            resp_clss = self.bytes_to_val(msg_resp[offset+i:offset+i+2])
            if resp_clss != 1:
                raise Exception("Unknown address class")
            i = i + 2 # jump to address ttl
            resp_ttl = self.bytes_to_val(msg_resp[offset+i:offset+i+4])
            i = i + 4 # jump to data length
            resp_addr_len = self.bytes_to_val(msg_resp[offset+i:offset+i+2])
            i = i + 2 # jump to the address
            if resp_type == 1:
                resp_addr = self.parse_address_a(resp_addr_len, msg_resp[offset+i:offset+i+resp_addr_len+1])
            elif resp_type == 28:
                resp_addr = self.parse_address_aaaa(resp_addr_len, msg_resp[offset+i:offset+i+resp_addr_len+1])
            else:
                raise Exception("Unknown address type")
            i = i + resp_addr_len
            answers.append((domain, resp_ttl, resp_addr))
            offset = offset + i
        
        return answers

    # major resolver
    def resolve(self, query_domain, query_type, server):
        self.format_query(query_domain, query_type)
        client_sckt = socket(AF_INET, SOCK_DGRAM)
        client_sckt.sendto(self.msg_qry, (server, PORT))
        (msg_resp, server_addr) = client_sckt.recvfrom(2048)
        client_sckt.close()
        
        return self.parse_response(msg_resp)
    
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
    d = DNSClient()
    #domain = input("Enter domain name\n")
    domain = "kyle.cs430.luther.edu"
    rec_type = input("Enter record type (A, AAAA)\n")
    #rec_type = "A"
    #server = input("Enter domain name server address\n")
    server = "localhost"
    ans = d.resolve(domain, rec_type, server)
    print(ans)
if __name__=="__main__":
    main()