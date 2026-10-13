import hashlib
import hmac
import json
import struct
import threading
import unittest
import transport

class Capture:
    def __init__(self):self.packets=[]
    def sendall(self,packet):self.packets.append(packet)

class TransportTests(unittest.TestCase):
    def peers(self):
        sender,receiver=Capture(),Capture()
        key=bytes(range(16))
        transport.configure(sender,key)
        transport.configure(receiver,key,server=True)
        return sender,receiver,key

    def frame(self,sender,payload):
        body=json.dumps(payload).encode()
        transport.send_packet(sender,struct.pack('!I',len(body))+body)
        return sender.packets[-1][4:]

    def test_tampering_replay_and_direction_are_rejected(self):
        sender,receiver,key=self.peers()
        frame=self.frame(sender,{'type':'private_chat','to':'bob','content':'ciphertext'})
        with self.assertRaises(ValueError):transport.decode(receiver,frame.replace(b'bob',b'eve'))
        self.assertEqual(transport.state_for(receiver).recv_seq,0)
        self.assertEqual(json.loads(transport.decode(receiver,frame))['to'],'bob')
        with self.assertRaises(ValueError):transport.decode(receiver,frame)
        reflected=Capture();transport.configure(reflected,key)
        with self.assertRaises(ValueError):transport.decode(reflected,frame)

    def test_plaintext_control_is_rejected(self):
        sender,receiver,_=self.peers()
        with self.assertRaises(ValueError):transport.decode(receiver,b'{"type":"group_disband","gid":"some-group"}')

    def test_concurrent_sends_are_in_sequence(self):
        sender,receiver,_=self.peers()
        threads=[threading.Thread(target=self.frame,args=(sender,{'index':i})) for i in range(30)]
        for worker in threads:worker.start()
        for worker in threads:worker.join()
        values=[json.loads(transport.decode(receiver,p[4:]))['index'] for p in sender.packets]
        self.assertEqual(sorted(values),list(range(30)))

    def test_wire_limit_includes_authentication_overhead(self):
        sender,receiver,_=self.peers()
        body=b'x'*transport.MAX_PAYLOAD_LEN
        transport.send_packet(sender,struct.pack('!I',len(body))+body)
        self.assertEqual(len(sender.packets[-1])-4,transport.MAX_WIRE_LEN)
        self.assertEqual(transport.decode(receiver,sender.packets[-1][4:]),body)
        with self.assertRaises(ValueError):transport.send_packet(sender,b'xxxx'+body+b'x')

    def test_cross_language_vector(self):
        sender,receiver,key=self.peers()
        body=b'{"type":"group_leave","gid":"g"}'
        transport.send_packet(sender,struct.pack('!I',len(body))+body)
        self.assertEqual(sender.packets[0][4:].hex(), '00000000000000007b2274797065223a2267726f75705f6c65617665222c22676964223a2267227d726a29b0e5069e813061c813a2775974391a9db833691553be4e467fe7bc0ade')
