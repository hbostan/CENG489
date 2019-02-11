#!/usr/bin/python

import socket
import struct
import argparse

class ETH:
	ProtoMap = {8:"IPv4", 56710:"IPv6", 1544:"ARP"}
	def __init__(self, data):
		dst, src, proto = struct.unpack('!6s6sH', data[:14])
		self.dst_mac = self.MacFromBytes(dst)
		self.src_mac = self.MacFromBytes(src)
		self.proto = socket.htons(proto)
		self.data = data[14:]

	def MacFromBytes(self, raw_mac):
		byte_str = map('{:02x}'.format, raw_mac)
		mac_addr = ":".join(byte_str).upper()
		return mac_addr
	def GetProto(self):
		return self.ProtoMap[self.proto]

class IPv4:
	ProtoMap = {1:"ICMP", 2:"IGMP", 4:"IP", 6:"TCP", 17:"UDP"}
	def __init__(self, data):
		v_hdr = data[0]
		self.version = v_hdr >> 4
		self.hdr_len = (v_hdr & 15) << 2
		ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])
		self.ttl = ttl
		self.proto = proto
		self.src = self.IpFromBytes(src)
		self.dst = self.IpFromBytes(dst)
		self.data = data[self.hdr_len:]

	def IpFromBytes(self, raw_ip):
		ip_str =".".join(map(str, raw_ip))
		return ip_str

	def GetProto(self):
		return self.ProtoMap[self.proto]

class ICMP:
	TypeMap = {0:"Echo Reply",3:"Destination Unreachable", 4:"Source Quench",
					5:"Redirect", 8:"Echo Request",11:"Time Exceeded"
					, 30:"Traceroute", 37:"Domain Name Request", 38:"Domain Name Reply"}
	def __init__(self, data):
		type, code, cs = struct.unpack('!BBH', data[:4])
		self.type = type
		self.code = code
		self.checksum = cs
		self.data = data[4:]

	def GetType(self):
		return self.TypeMap[self.type]

class TCP:
	def __init__(self, data):
		src_port, dst_port, seq, ack, flags = struct.unpack('!HHLLH', data[:14])
		self.offset = (flags >> 12) << 2
		self.src_port = src_port
		self.dst_port = dst_port
		self.seq = seq
		self.urg = (flags & 32) >> 5
		self.ack = (flags & 16) >> 4
		self.psh = (flags & 8) >> 3
		self.rst = (flags & 4) >> 2
		self.syn = (flags & 2) >> 1
		self.fin = (flags & 1)
		try:
			self.data = data[self.offset:].decode("utf-8")
		except:
			self.data = data[self.offset:]

class UDP:
	def __init__(self, data):
		self.src_port, self.dst_port, self.size = struct.unpack('!HH2xH', data[:8])
		try:
			self.data = data[8:].decode("utf-8")
		except:
			self.data = data[8:]

def CheckIpString(addr):
	if addr == '*':
		return True
	try:
		addr = [int(x) for x in addr.split('.')]
	except:
		return False
	if(len(addr) != 4):
		return False
	for i in addr:
		if i not in range(0,256):
			return False
	return True

def GetPortRange(ports):
	if ports == '*':
		return (0, 65535)
	try:
		ports = [int(x) for x in ports.split(':')]
	except:
		return False
	if len(ports) > 2:
		return False
	for p in ports:
		if p not in range(0, 65536):
			return False
	if len(ports) == 1:
		return (ports[0], ports[0])
	if ports[0] > ports[1]:
		return False
	return (ports[0], ports[1])

def ParseArgs():
	parser = argparse.ArgumentParser(description="A simple packet sniffer.")
	parser.add_argument('--proto', type=str, help="Filter packets with given IPv4 protocol", default='*', choices=["icmp", "tcp", "udp"])
	parser.add_argument('-s', '--source_ip', type=str, help="Filter packets with source ip", default='*')
	parser.add_argument('-d', '--dest_ip', type=str, help="Filter packets with destination ip", default='*')
	parser.add_argument('-p', '--port', type=str, help="Port number or range", default='*')
	args = parser.parse_args()
	if not CheckIpString(args.source_ip):
		print("Invalid source_ip")
		exit(1)
	if not CheckIpString(args.dest_ip):
		print("Invalid dest_ip")
		exit(1)
	port_range = GetPortRange(args.port)
	if not port_range:
		print("Invalid port range")
		exit(1)
	return args.proto, args.source_ip, args.dest_ip, port_range


#              NO    ETH         IP     IP       Source  Dest    DATA
FRMT_STR = "|{:^5s}|{:^5s}|{:^5s}|{:^15s} -> {:^15s}|{:^8s}|{:^8s}|{:s}"

def main():
	args = ParseArgs()
	filter_proto = args[0]
	filter_sip = args[1]
	filter_dip = args[2]
	filter_plo = args[3][0]
	filter_phi = args[3][1]
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x3))
	pn = 0
	while True:
		try:
			ps = FRMT_STR
			raw_data, addr = sock.recvfrom(65535)
			pn+=1
			eth = ETH(raw_data)
			# IPv4
			if eth.proto == 8:
				ipv4 = IPv4(eth.data)
				if(filter_sip in [ipv4.src, '*'] and filter_dip in [ipv4.dst, '*']):
					# ICMP
					if(ipv4.proto == 1 and filter_proto in ['icmp','*']):
						icmp = ICMP(ipv4.data)
						ps = ps.format(str(pn),eth.GetProto(),ipv4.GetProto(),ipv4.src, ipv4.dst, "---", "---",icmp.GetType())
					# TCP
					elif(ipv4.proto == 6 and filter_proto in ['tcp','*']):
						tcp = TCP(ipv4.data)
						if(tcp.src_port in range(filter_plo, filter_phi+1) or tcp.dst_port in range(filter_plo, filter_phi+1)):
							ps = ps.format(str(pn),eth.GetProto(),ipv4.GetProto(),ipv4.src, ipv4.dst, str(tcp.src_port), str(tcp.dst_port), str(tcp.data).replace('\n', ' ').replace('\r', ' '))
						else:
							continue
					# UDP
					elif(ipv4.proto == 17 and filter_proto in ['udp','*']):
						udp = UDP(ipv4.data)
						if(udp.src_port in range(filter_plo, filter_phi+1) or udp.dst_port in range(filter_plo, filter_phi+1)):
							ps = ps.format(str(pn),eth.GetProto(),ipv4.GetProto(),ipv4.src, ipv4.dst, str(udp.src_port), str(udp.dst_port), str(udp.data).replace('\n', ' ').replace('\r', ' '))
						else:
							continue
					else:
						continue
				else:
					continue
			# IPv6
			else:
				continue
			print(ps)
		except KeyboardInterrupt:
			print("Interrupt Received, exiting...")
			break


main()