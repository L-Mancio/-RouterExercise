

"""
This component is a mininet exercise, specifically the Firewall exercise
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt #ipv4, arp..
import pox.lib.addresses as adr #EthAddr , IPAddr ..

log = core.getLogger()



class Tutorial (object):
	def __init__ (self, connection):

		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

		#self.dpid_table = {'10.0.1.1': 1, '10.0.2.1': 2}
		# Use this table to keep track of which ethernet address is on
		# which switch port (keys are MACs, values are ports).
		self.ip_to_port = {}
		self.mac_to_port = {}

		self.routing_table = { '10.0.1.0/24', '10.0.2.0/24'}
		#ip to mac
		self.arp_table = {}

		self.block_ports = {5001}


	def act_like_router (self, packet, packet_in):
		#handle ARP Requests and replies
		etherPayload = packet.payload #the stripped ethFrame, contains ipv4 or arp packet
		src_mac = packet.src
		dst_mac = packet.dst

		if packet.type == pkt.ethernet.ARP_TYPE:
			src_ip = etherPayload.protosrc
			dst_ip = etherPayload.protodst
			if etherPayload.opcode == pkt.arp.REQUEST:
				print("received ARP REQUEST checking if i have info on sender: " + str(src_mac))

				if src_mac not in self.mac_to_port:
					print("sender mac unknown, adding to mac table...")
					self.mac_to_port[src_mac] = packet_in.in_port
				if src_ip not in self.arp_table:
					print("sender ip unknown, adding to arp table...")
					self.arp_table[src_ip] = src_mac
				if src_ip not in self.ip_to_port:
					print("sender ip unknown, adding to ip table...")
					self.ip_to_port[src_ip] = packet_in.in_port

				self.displayTables()

				#creating arp reply to send back
				arp_reply = pkt.arp()
				arp_reply.hwsrc = adr.EthAddr("11:12:13:14:15:16")  # fake mac in response
				arp_reply.hwdst = etherPayload.hwsrc
				arp_reply.opcode = pkt.arp.REPLY
				arp_reply.protosrc = etherPayload.protodst
				arp_reply.protodst = etherPayload.protosrc

				# encapsulate in ethernet frame now
				ether = pkt.ethernet()
				ether.type = pkt.ethernet.ARP_TYPE
				ether.dst = packet.src
				ether.src = packet.dst
				ether.payload = arp_reply

				#sending packet to switch
				self.resend_packet(ether, packet_in.in_port)


		elif packet.type == pkt.ethernet.IP_TYPE:
			if etherPayload.protocol == pkt.ipv4.ICMP_PROTOCOL:
				icmp_packet = etherPayload.payload
				src_ip = etherPayload.srcip
				dst_ip = etherPayload.dstip
				k = 0 #subnet holder
				if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:

					if src_mac not in self.mac_to_port:
						print("sender mac unknown, adding to mac table...")
						self.mac_to_port[src_mac] = packet_in.in_port
					if src_ip not in self.arp_table:
						print("sender ip unknown, adding to arp table...")
						self.arp_table[src_ip] = src_mac
					if src_ip not in self.ip_to_port:
						print("sender ip unknown, adding to ip table...")
						self.ip_to_port[src_ip] = packet_in.in_port

					self.displayTables()

					for subnet in self.routing_table:
						if dst_ip.inNetwork(subnet):
							k = subnet
					if k!=0:
						#create ping reply
						# create echo fields
						ech = pkt.echo()  # echo contained in pkt.icmp
						ech.id = icmp_packet.payload.id
						ech.seq = icmp_packet.payload.seq + 1

						# encapsulates in icmp
						icmp_reply = pkt.icmp()
						icmp_reply.type = pkt.TYPE_ECHO_REPLY  # code 0
						icmp_reply.payload = ech

						# encapsulates in ipv4
						ip_p = pkt.ipv4()
						ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
						ip_p.srcip = dst_ip
						ip_p.dstip = src_ip
						ip_p.payload = icmp_reply

						# encapsulates in ethernet
						eth_p = pkt.ethernet()
						eth_p.type = pkt.ethernet.IP_TYPE
						eth_p.src = packet.dst
						eth_p.dst = packet.src
						eth_p.payload = ip_p

						msg = of.ofp_packet_out()
						msg.data = eth_p.pack()
						action = of.ofp_action_output(port=packet_in.in_port)
						msg.actions.append(action)
						self.connection.send(msg)

						print("echo Reply sent!")
						self.createflow(packet_in, eth_p, packet_in.in_port)

					else:
						print("ICMP destination unreachable")

						unr = pkt.unreach()
						unr.payload = etherPayload

						icmp_reply = pkt.icmp()
						icmp_reply.type = pkt.TYPE_DEST_UNREACH
						icmp_reply.payload = unr

						ip_p = pkt.ipv4()
						ip_p.srcip = dst_ip
						ip_p.dstip = src_ip
						ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
						ip_p.payload = icmp_reply

						eth_p = pkt.ethernet()
						eth_p.type = pkt.ethernet.IP_TYPE
						eth_p.dst = packet.src
						eth_p.src = packet.dst
						eth_p.payload = ip_p

						msg = of.ofp_packet_out()
						msg.data = eth_p.pack()
						action = of.ofp_action_output(port=packet_in.in_port)
						msg.actions.append(action)
						self.connection.send(msg)
						print("echo Unreachable Reply sent!")
						self.createflow(packet_in, eth_p, packet_in.in_port)

			#other type of ip packet maybe udp or tcp
			else:
				src_ip = etherPayload.srcip
				dst_ip = etherPayload.dstip

				if dst_ip in self.ip_to_port and dst_ip in self.arp_table:
					print("received other type of packet sending reply...")
					out_port = self.ip_to_port[dst_ip]
					eth_dest = self.arp_table[dst_ip]

					msg = of.ofp_packet_out()
					packet.src = packet.dst #since who received the packet is sending the reply set src = dst
					packet.dst = adr.EthAddr(eth_dest)
					msg.data = packet.pack()
					action = of.ofp_action_output(port = out_port)
					msg.actions.append(action)

					self.connection.send(msg)
					self.createflow(packet_in, packet, out_port)
				else:
					print("who do i send this to I am switch: " + str(self.connection.dpid))
					print("packet src ip: " + str(src_ip) + " to: "  + str(dst_ip))
					self.resend_packet(packet, of.OFPP_ALL)
					self.createflow(packet_in, packet, of.OFPP_ALL)



	def createflow(self, packet_in, packet, out_port):
		print("Creating Flow... for SWITCH: " + str(self.connection.dpid))

		#keeping the flow matches low increases the range of matches hence, few matching rules overlapping
		msg = of.ofp_flow_mod()
		#msg.match = of.ofp_match.from_packet(packet)
		#
		#msg.match.in_port = packet_in.in_port  # don't need this
		msg.match.dl_src = packet.src
		msg.match.dl_dst = packet.dst
		#if packet.type == pkt.ethernet.ARP_TYPE:
			#msg.match.nw_src = packet.payload.protosrc
			#msg.match.nw_dst = packet.payload.protodst
		#else:
			#msg.match.nw_src = packet.payload.srcip
			#msg.match.nw_dst = packet.payload.dstip
		#

		#msg.buffer_id = packet_in.buffer_id
		action = of.ofp_action_output(port = out_port)
		msg.actions.append(action)
		self.connection.send(msg)

	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""
		packet = event.parsed # This is the ethernet packet.
		#tcpp = event.parsed.find('tcp')
		if not packet.find('tcp'):
			#return
			if not packet.parsed:
				log.warning("Ignoring incomplete packet")
				return
			packet_in = event.ofp  # The actual ofp_packet_in message.
			self.act_like_router(packet, packet_in)
		elif packet.find('tcp').dstport in self.block_ports or packet.find('tcp').srcport in self.block_ports:
			core.getLogger("blocker").debug("Blocked TCP %s <-> %s", packet.find('tcp').srcport, packet.find('tcp').dstport)
			event.halt = True


	def resend_packet(self, packet_in, out_port):
		"""
		Instructs the switch to resend a packet that it had sent to us.
		"packet_in" is the ofp_packet_in object the switch had sent to the
		controller due to a table-miss.
		"""
		msg = of.ofp_packet_out()
		msg.data = packet_in.pack()

		# Add an action to send to the specified port
		action = of.ofp_action_output(port=out_port)
		msg.actions.append(action)

		# Send message to switch
		self.connection.send(msg)

	def displayTables(self):

		if self.connection.dpid == 1:
			print("mac, ip, and arp tables for Switch 1:")
			print(self.mac_to_port)
			print(self.ip_to_port)
			print(self.arp_table)
		elif self.connection.dpid == 2:
			print("mac, ip, and arp tables for Switch 2:")
			print(self.mac_to_port)
			print(self.ip_to_port)
			print(self.arp_table)

def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Tutorial(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
