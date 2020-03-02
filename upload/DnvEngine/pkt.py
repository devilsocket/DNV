from pprint import pprint
from dpkt.pcap import Reader
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP
from dpkt.dns import DNS
from dpkt.tcp import TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR
from socket import inet_ntoa
from datetime import datetime
from dpkt.dpkt import UnpackError
from django.conf import settings
import os, json, stat, time
import sys
import socket
import hashlib
import pandas as pd 
from netaddr import all_matching_cidrs

subnet_config = pd.read_csv(os.path.join(settings.MEDIA_ROOT,'DNV_SIGNATURES','subnet_config.csv')) 
subnets = subnet_config.subnet.values

dns_config = pd.read_csv(os.path.join(settings.MEDIA_ROOT,'DNV_SIGNATURES','dns_config.csv'))
dns_list = dns_config['domain'].to_list()
dnss = dns_config.domain.values

def DnsRequestParser(udp):
	res = {}
	dns = False
	try:dns = DNS(udp.data)
	except (UnpackError):pass
	if dns:
		if 'qd' in dns.__hdr_fields__:
			if dns.qd:
				res['domain'] = dns.qd[0].name.__str__()
				res['type'] = 'dns_request'
	return res

def DnsResponseParser(udp):
	res = {}
	dns = False
	try:dns = DNS(udp.data)
	except (UnpackError):pass
	if dns:
		if 'qd' in dns.__hdr_fields__:
			if dns.qd:
				res['domain'] = dns.qd[0].name.__str__()
				res['type'] = 'dns_response'
				res['answers'] = []
				if 'an' in dns.__hdr_fields__:
					for answer in dns.an:
						if answer.type == 1:
							res['answers'].append(
									{
										'answer' : answer.name.__str__(),
										'ip' : inet_ntoa(answer.ip)
									}
								)
	return res

def UdpPacketParser(ip_layer):
	res = {}
	udp = ip_layer.data
	udph = False
	try:udph = udp.__hdr__
	except (AttributeError) as err:print(err)
	if udph:
		if udp.dport:
			if udp.dport == 53:
				dns = False
				try:dns = DNS(udp.data)
				except (UnpackError):pass
				if dns:
					res['domain'] = dns.qd[0].name.__str__()
					res['dp'] = udp.dport
					res['type'] = 'dns_request'
			elif udp.sport == 53:
				dns = False
				try:dns = DNS(udp.data)
				except (UnpackError):pass
				if dns:
					res['domain'] = dns.qd[0].name.__str__()
					res['sp'] = udp.sport
					res['type'] = 'dns_answer'
	return res

def PacketDiessector(pcap_path, upload_id):
	def flagScanner(tcp):
		result = []
		if ( tcp.flags & TH_FIN ) != 0:
			result.append('fin')
		if ( tcp.flags & TH_SYN ) != 0:
			result.append('syn')
		if ( tcp.flags & TH_RST ) != 0:
			result.append('rst')
		if ( tcp.flags & TH_PUSH ) != 0:
			result.append('psh')
		if ( tcp.flags & TH_ACK ) != 0:
			result.append('ack')
		if ( tcp.flags & TH_URG ) != 0:
			result.append('urg')
		if ( tcp.flags & TH_ECE ) != 0:
			result.append('ece')
		if ( tcp.flags & TH_CWR ) != 0:
			result.append('cwr')
		return result

	#print("[+] scanning : {}".format(pcap_path))
	domains = {}
	sessions = {}
	complete = []
	#incomplete = []
	with open(pcap_path,'rb') as pf:
		pcap_file_name = pcap_path
		dpkt_file_object = False
		try:dpkt_file_object = Reader(pf)
		except Exception as err:
			dpkt_file_object = False
			#print("[-] pcap corruption detected : {}".format(pcap_path))
		if dpkt_file_object:
			#print("[+] pcap's health fine : {}".format(pcap_path))
			for ts, payload in dpkt_file_object:
				t1, p = ts, payload
				t = datetime.fromtimestamp(t1).strftime("%Y-%m-%d %H:%M:%S")
				eth = False
				try:eth = Ethernet(payload)
				except:eth = False
				
				if eth:
					if eth.type == 2048:
						ip = eth.data
						src_ip = inet_ntoa(ip.src)
						dst_ip = inet_ntoa(ip.dst)
						if ip.p == 17:
							udp_pkt_header = False
							udp = ip.data
							try:udp_pkt_header = udp.__hdr__
							except:udp_pkt_header = False
							if udp_pkt_header:
								udp_src_port, udp_dst_port = udp.sport, udp.dport
								if udp_src_port == 53:
									dns_response_data = DnsResponseParser(udp)
									dns_response_data['src_ip'], dns_response_data['dst_ip'] = src_ip, dst_ip
									dns_response_data['src_port'], dns_response_data['dst_port'] = udp_src_port, udp_dst_port
									dns_response_data['dns_time'] = t
									dns_response_data['upload_id'] = upload_id
									domains[dst_ip] = dns_response_data
								elif udp_dst_port == 53:
									dns_request_data = DnsRequestParser(udp)
									dns_request_data['src_ip'], dns_request_data['dst_ip'] = src_ip, dst_ip
									dns_request_data['src_port'], dns_request_data['dst_port'] = udp_src_port, udp_dst_port
									dns_request_data['dns_time'] = t
									dns_request_data['upload_id'] = upload_id
									domains[src_ip] = dns_request_data
						elif ip.p == 6:
							tcp_pkt_header = False
							tcp = ip.data
							try:tcp_pkt_header = udp.__hdr__
							except:tcp_pkt_header = False
							if tcp_pkt_header:
								tcp_packet_data = {}
								tcp_packet_data['upload_id'] = upload_id
								tcp_packet_data['pcap_file_path'] = pcap_file_name.split('media')[-1]
								tcp_packet_data['src_ip'], tcp_packet_data['dst_ip'], tcp_packet_data['pkts_num'] = src_ip, dst_ip, 1
								tcp_src_port, tcp_dst_port = tcp.sport, tcp.dport
								tcp_packet_data['src_port'], tcp_packet_data['dst_port'] = tcp_src_port, tcp_dst_port
								flags = flagScanner(tcp)
								tcp_packet_data['pkts_size'] = tcp.data.__len__()
								uni_key = '{}{}{}{}'.format(tcp_packet_data['src_ip'],tcp_packet_data['src_port'],tcp_packet_data['dst_ip'],tcp_packet_data['dst_port'])
								
								if 'syn' in flags:
									if uni_key in sessions:del sessions[uni_key]
									tcp_packet_data['start_time'] = t
									tcp_packet_data['end_time'] = t
									tcp_packet_data['session'] = False
									tcp_packet_data['dns_data'] = False
									if tcp_packet_data['src_ip'] in domains:
										tcp_packet_data['dns_data'] = domains[tcp_packet_data['src_ip']]
									if tcp_packet_data['dst_ip'] in domains:
										tcp_packet_data['dns_data'] = domains[tcp_packet_data['dst_ip']]
									sessions[uni_key] = tcp_packet_data
								elif 'fin' in flags:
									if uni_key in sessions:
										sessions[uni_key]['pkts_num']+=tcp_packet_data['pkts_num']
										sessions[uni_key]['pkts_size']+=tcp_packet_data['pkts_size']
										sessions[uni_key]['session'] = True
										sessions[uni_key]['end_time'] = t
										complete_session = sessions[uni_key]
										complete.append(complete_session)
										del sessions[uni_key]
								else:
									if uni_key in sessions:
										sessions[uni_key]['pkts_num']+=tcp_packet_data['pkts_num']
										sessions[uni_key]['pkts_size']+=tcp_packet_data['pkts_size']
										sessions[uni_key]['end_time'] = t
	for session in sessions:
		complete.append(sessions[session])
	for sess in complete:
		# phase one scan
		sess['phase_one_scan'] = False
		detected_subnets = []
		src_subnets = all_matching_cidrs(sess['src_ip'], subnets)
		dst_subnets = all_matching_cidrs(sess['dst_ip'], subnets)
		if src_subnets:detected_subnets.append(str(src_subnets[0]))
		if dst_subnets:detected_subnets.append(str(dst_subnets[0]))
		if detected_subnets:
			detected_subnet = detected_subnets[0]
			sess['phase_one_scan'] = subnet_config.loc[subnet_config['subnet'] == detected_subnet].to_dict()
			ddf = subnet_config.loc[subnet_config['subnet'] == detected_subnet].to_dict()
			sess['phase_one_scan'] = {
				'subnet' : list(ddf['subnet'].values())[0].strip(),
				'application' : list(ddf['application'].values())[0].strip(),
				'activity' : list(ddf['activity'].values())[0].strip(),
				'category' : list(ddf['category'].values())[0].strip()
			}
		# phase two scan
		sess['phase_two_scan'] = False
		if sess['dns_data']:
			sess['phase_two_scan'] = False
			detected_dnss = []
			if 'domain' in sess['dns_data']:
				domain = sess['dns_data']['domain']
				for item in dns_list:
					if item in domain:
						detected_dnss.append(item.strip())
				if detected_dnss:
					df = dns_config.loc[dns_config['domain'] == detected_dnss[0]].to_dict()
					sess['phase_two_scan'] = {
						'domain' : list(df['domain'].values())[0].strip(),
						'application' : list(df['application'].values())[0].strip(),
						'activity' : list(df['activity'].values())[0].strip(),
						'category' : list(df['category'].values())[0].strip()
					}
		sess['hash'] = hashlib.md5(str(sess.values()).encode('utf-8')).hexdigest()
	return complete
