#
# Copyright (c) 2008-2015 Citrix Systems, Inc.
#
#   Licensed under the Apache License, Version 2.0 (the "License")
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

from nssrc.com.citrix.netscaler.nitro.resource.base.base_resource import base_resource
from nssrc.com.citrix.netscaler.nitro.resource.base.base_resource import base_response
from nssrc.com.citrix.netscaler.nitro.service.options import options
from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception

from nssrc.com.citrix.netscaler.nitro.util.nitro_util import nitro_util

class nspbr6(base_resource) :
	""" Configuration for PBR6 entry resource. """
	def __init__(self) :
		self._name = ""
		self._td = 0
		self._action = ""
		self._srcipv6 = False
		self._srcipop = ""
		self._srcipv6val = ""
		self._srcport = False
		self._srcportop = ""
		self._srcportval = ""
		self._destipv6 = False
		self._destipop = ""
		self._destipv6val = ""
		self._destport = False
		self._destportop = ""
		self._destportval = ""
		self._srcmac = ""
		self._protocol = ""
		self._protocolnumber = 0
		self._vlan = 0
		self._vxlan = 0
		self._Interface = ""
		self._priority = 0
		self._state = ""
		self._msr = ""
		self._monitor = ""
		self._nexthop = False
		self._nexthopval = ""
		self._nexthopvlan = 0
		self._detail = False
		self._kernelstate = ""
		self._hits = 0
		self._curstate = 0
		self._totalprobes = 0
		self._totalfailedprobes = 0
		self._failedprobes = 0
		self._monstatcode = 0
		self._monstatparam1 = 0
		self._monstatparam2 = 0
		self._monstatparam3 = 0
		self._data = False
		self.___count = 0

	@property
	def name(self) :
		"""Name for the PBR6. Must begin with an ASCII alphabetic or underscore \(_\) character, and must contain only ASCII alphanumeric, underscore, hash \(\#\), period \(.\), space, colon \(:\), at \(@\), equals \(=\), and hyphen \(-\) characters. Can be changed after the PBR6 is created.<br/>Minimum length =  1.
		"""
		try :
			return self._name
		except Exception as e:
			raise e

	@name.setter
	def name(self, name) :
		"""Name for the PBR6. Must begin with an ASCII alphabetic or underscore \(_\) character, and must contain only ASCII alphanumeric, underscore, hash \(\#\), period \(.\), space, colon \(:\), at \(@\), equals \(=\), and hyphen \(-\) characters. Can be changed after the PBR6 is created.<br/>Minimum length =  1
		"""
		try :
			self._name = name
		except Exception as e:
			raise e

	@property
	def td(self) :
		"""Integer value that uniquely identifies the traffic domain in which you want to configure the entity. If you do not specify an ID, the entity becomes part of the default traffic domain, which has an ID of 0.<br/>Maximum length =  4094.
		"""
		try :
			return self._td
		except Exception as e:
			raise e

	@td.setter
	def td(self, td) :
		"""Integer value that uniquely identifies the traffic domain in which you want to configure the entity. If you do not specify an ID, the entity becomes part of the default traffic domain, which has an ID of 0.<br/>Maximum length =  4094
		"""
		try :
			self._td = td
		except Exception as e:
			raise e

	@property
	def action(self) :
		"""Action to perform on the outgoing IPv6 packets that match the PBR6.
		Available settings function as follows:
		* ALLOW - The NetScaler appliance sends the packet to the designated next-hop router.
		* DENY - The NetScaler appliance applies the routing table for normal destination-based routing.<br/>Possible values = ALLOW, DENY.
		"""
		try :
			return self._action
		except Exception as e:
			raise e

	@action.setter
	def action(self, action) :
		"""Action to perform on the outgoing IPv6 packets that match the PBR6.
		Available settings function as follows:
		* ALLOW - The NetScaler appliance sends the packet to the designated next-hop router.
		* DENY - The NetScaler appliance applies the routing table for normal destination-based routing.<br/>Possible values = ALLOW, DENY
		"""
		try :
			self._action = action
		except Exception as e:
			raise e

	@property
	def srcipv6(self) :
		"""IP address or range of IP addresses to match against the source IP address of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			return self._srcipv6
		except Exception as e:
			raise e

	@srcipv6.setter
	def srcipv6(self, srcipv6) :
		"""IP address or range of IP addresses to match against the source IP address of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			self._srcipv6 = srcipv6
		except Exception as e:
			raise e

	@property
	def srcipop(self) :
		"""Either the equals (=) or does not equal (!=) logical operator.<br/>Possible values = =, !=, EQ, NEQ.
		"""
		try :
			return self._srcipop
		except Exception as e:
			raise e

	@srcipop.setter
	def srcipop(self, srcipop) :
		"""Either the equals (=) or does not equal (!=) logical operator.<br/>Possible values = =, !=, EQ, NEQ
		"""
		try :
			self._srcipop = srcipop
		except Exception as e:
			raise e

	@property
	def srcipv6val(self) :
		"""IP address or range of IP addresses to match against the source IP address of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			return self._srcipv6val
		except Exception as e:
			raise e

	@srcipv6val.setter
	def srcipv6val(self, srcipv6val) :
		"""IP address or range of IP addresses to match against the source IP address of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			self._srcipv6val = srcipv6val
		except Exception as e:
			raise e

	@property
	def srcport(self) :
		"""Port number or range of port numbers to match against the source port number of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets. For example: [40-90].
		"""
		try :
			return self._srcport
		except Exception as e:
			raise e

	@srcport.setter
	def srcport(self, srcport) :
		"""Port number or range of port numbers to match against the source port number of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets. For example: [40-90].
		"""
		try :
			self._srcport = srcport
		except Exception as e:
			raise e

	@property
	def srcportop(self) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ.
		"""
		try :
			return self._srcportop
		except Exception as e:
			raise e

	@srcportop.setter
	def srcportop(self, srcportop) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ
		"""
		try :
			self._srcportop = srcportop
		except Exception as e:
			raise e

	@property
	def srcportval(self) :
		"""Source port (range).<br/>Maximum length =  65535.
		"""
		try :
			return self._srcportval
		except Exception as e:
			raise e

	@srcportval.setter
	def srcportval(self, srcportval) :
		"""Source port (range).<br/>Maximum length =  65535
		"""
		try :
			self._srcportval = srcportval
		except Exception as e:
			raise e

	@property
	def destipv6(self) :
		"""IP address or range of IP addresses to match against the destination IP address of an outgoing IPv6 packet.  In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			return self._destipv6
		except Exception as e:
			raise e

	@destipv6.setter
	def destipv6(self, destipv6) :
		"""IP address or range of IP addresses to match against the destination IP address of an outgoing IPv6 packet.  In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			self._destipv6 = destipv6
		except Exception as e:
			raise e

	@property
	def destipop(self) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ.
		"""
		try :
			return self._destipop
		except Exception as e:
			raise e

	@destipop.setter
	def destipop(self, destipop) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ
		"""
		try :
			self._destipop = destipop
		except Exception as e:
			raise e

	@property
	def destipv6val(self) :
		"""IP address or range of IP addresses to match against the destination IP address of an outgoing IPv6 packet.  In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			return self._destipv6val
		except Exception as e:
			raise e

	@destipv6val.setter
	def destipv6val(self, destipv6val) :
		"""IP address or range of IP addresses to match against the destination IP address of an outgoing IPv6 packet.  In the command line interface, separate the range with a hyphen and enclose within brackets.
		"""
		try :
			self._destipv6val = destipv6val
		except Exception as e:
			raise e

	@property
	def destport(self) :
		"""Port number or range of port numbers to match against the destination port number of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets. For example: [40-90].
		Note: The destination port can be specified only for TCP and UDP protocols.
		"""
		try :
			return self._destport
		except Exception as e:
			raise e

	@destport.setter
	def destport(self, destport) :
		"""Port number or range of port numbers to match against the destination port number of an outgoing IPv6 packet. In the command line interface, separate the range with a hyphen and enclose within brackets. For example: [40-90].
		Note: The destination port can be specified only for TCP and UDP protocols.
		"""
		try :
			self._destport = destport
		except Exception as e:
			raise e

	@property
	def destportop(self) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ.
		"""
		try :
			return self._destportop
		except Exception as e:
			raise e

	@destportop.setter
	def destportop(self, destportop) :
		"""Logical operator.<br/>Possible values = =, !=, EQ, NEQ
		"""
		try :
			self._destportop = destportop
		except Exception as e:
			raise e

	@property
	def destportval(self) :
		"""Destination port (range).<br/>Maximum length =  65535.
		"""
		try :
			return self._destportval
		except Exception as e:
			raise e

	@destportval.setter
	def destportval(self, destportval) :
		"""Destination port (range).<br/>Maximum length =  65535
		"""
		try :
			self._destportval = destportval
		except Exception as e:
			raise e

	@property
	def srcmac(self) :
		"""MAC address to match against the source MAC address of an outgoing IPv6 packet.
		"""
		try :
			return self._srcmac
		except Exception as e:
			raise e

	@srcmac.setter
	def srcmac(self, srcmac) :
		"""MAC address to match against the source MAC address of an outgoing IPv6 packet.
		"""
		try :
			self._srcmac = srcmac
		except Exception as e:
			raise e

	@property
	def protocol(self) :
		"""Protocol, identified by protocol name, to match against the protocol of an outgoing IPv6 packet.<br/>Possible values = ICMPV6, TCP, UDP.
		"""
		try :
			return self._protocol
		except Exception as e:
			raise e

	@protocol.setter
	def protocol(self, protocol) :
		"""Protocol, identified by protocol name, to match against the protocol of an outgoing IPv6 packet.<br/>Possible values = ICMPV6, TCP, UDP
		"""
		try :
			self._protocol = protocol
		except Exception as e:
			raise e

	@property
	def protocolnumber(self) :
		"""Protocol, identified by protocol number, to match against the protocol of an outgoing IPv6 packet.<br/>Minimum length =  1<br/>Maximum length =  255.
		"""
		try :
			return self._protocolnumber
		except Exception as e:
			raise e

	@protocolnumber.setter
	def protocolnumber(self, protocolnumber) :
		"""Protocol, identified by protocol number, to match against the protocol of an outgoing IPv6 packet.<br/>Minimum length =  1<br/>Maximum length =  255
		"""
		try :
			self._protocolnumber = protocolnumber
		except Exception as e:
			raise e

	@property
	def vlan(self) :
		"""ID of the VLAN. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified VLAN. If you do not specify an interface ID, the appliance compares the PBR6 to the outgoing packets on all VLANs.<br/>Minimum length =  1<br/>Maximum length =  4094.
		"""
		try :
			return self._vlan
		except Exception as e:
			raise e

	@vlan.setter
	def vlan(self, vlan) :
		"""ID of the VLAN. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified VLAN. If you do not specify an interface ID, the appliance compares the PBR6 to the outgoing packets on all VLANs.<br/>Minimum length =  1<br/>Maximum length =  4094
		"""
		try :
			self._vlan = vlan
		except Exception as e:
			raise e

	@property
	def vxlan(self) :
		"""ID of the VXLAN. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified VXLAN. If you do not specify an interface ID, the appliance compares the PBR6 to the outgoing packets on all VXLANs.<br/>Minimum length =  1<br/>Maximum length =  16777215.
		"""
		try :
			return self._vxlan
		except Exception as e:
			raise e

	@vxlan.setter
	def vxlan(self, vxlan) :
		"""ID of the VXLAN. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified VXLAN. If you do not specify an interface ID, the appliance compares the PBR6 to the outgoing packets on all VXLANs.<br/>Minimum length =  1<br/>Maximum length =  16777215
		"""
		try :
			self._vxlan = vxlan
		except Exception as e:
			raise e

	@property
	def Interface(self) :
		"""ID of an interface. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified interface. If you do not specify a value, the appliance compares the PBR6 to the outgoing packets on all interfaces.
		"""
		try :
			return self._Interface
		except Exception as e:
			raise e

	@Interface.setter
	def Interface(self, Interface) :
		"""ID of an interface. The NetScaler appliance compares the PBR6 only to the outgoing packets on the specified interface. If you do not specify a value, the appliance compares the PBR6 to the outgoing packets on all interfaces.
		"""
		try :
			self._Interface = Interface
		except Exception as e:
			raise e

	@property
	def priority(self) :
		"""Priority of the PBR6, which determines the order in which it is evaluated relative to the other PBR6s. If you do not specify priorities while creating PBR6s, the PBR6s are evaluated in the order in which they are created.<br/>Minimum length =  1<br/>Maximum length =  80000.
		"""
		try :
			return self._priority
		except Exception as e:
			raise e

	@priority.setter
	def priority(self, priority) :
		"""Priority of the PBR6, which determines the order in which it is evaluated relative to the other PBR6s. If you do not specify priorities while creating PBR6s, the PBR6s are evaluated in the order in which they are created.<br/>Minimum length =  1<br/>Maximum length =  80000
		"""
		try :
			self._priority = priority
		except Exception as e:
			raise e

	@property
	def state(self) :
		"""Enable or disable the PBR6. After you apply the PBR6s, the NetScaler appliance compares outgoing packets to the enabled PBR6s.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._state
		except Exception as e:
			raise e

	@state.setter
	def state(self, state) :
		"""Enable or disable the PBR6. After you apply the PBR6s, the NetScaler appliance compares outgoing packets to the enabled PBR6s.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._state = state
		except Exception as e:
			raise e

	@property
	def msr(self) :
		"""Monitor the route specified by the Next Hop parameter.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._msr
		except Exception as e:
			raise e

	@msr.setter
	def msr(self, msr) :
		"""Monitor the route specified by the Next Hop parameter.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._msr = msr
		except Exception as e:
			raise e

	@property
	def monitor(self) :
		"""The name of the monitor.(Can be only of type ping or ARP ).<br/>Minimum length =  1.
		"""
		try :
			return self._monitor
		except Exception as e:
			raise e

	@monitor.setter
	def monitor(self, monitor) :
		"""The name of the monitor.(Can be only of type ping or ARP ).<br/>Minimum length =  1
		"""
		try :
			self._monitor = monitor
		except Exception as e:
			raise e

	@property
	def nexthop(self) :
		"""IP address of the next hop router to which to send matching packets if action is set to ALLOW. This next hop should be directly reachable from the appliance.
		"""
		try :
			return self._nexthop
		except Exception as e:
			raise e

	@nexthop.setter
	def nexthop(self, nexthop) :
		"""IP address of the next hop router to which to send matching packets if action is set to ALLOW. This next hop should be directly reachable from the appliance.
		"""
		try :
			self._nexthop = nexthop
		except Exception as e:
			raise e

	@property
	def nexthopval(self) :
		"""The Next Hop IPv6 address.
		"""
		try :
			return self._nexthopval
		except Exception as e:
			raise e

	@nexthopval.setter
	def nexthopval(self, nexthopval) :
		"""The Next Hop IPv6 address.
		"""
		try :
			self._nexthopval = nexthopval
		except Exception as e:
			raise e

	@property
	def nexthopvlan(self) :
		"""VLAN number to be used for link local nexthop .<br/>Minimum length =  1<br/>Maximum length =  4094.
		"""
		try :
			return self._nexthopvlan
		except Exception as e:
			raise e

	@nexthopvlan.setter
	def nexthopvlan(self, nexthopvlan) :
		"""VLAN number to be used for link local nexthop .<br/>Minimum length =  1<br/>Maximum length =  4094
		"""
		try :
			self._nexthopvlan = nexthopvlan
		except Exception as e:
			raise e

	@property
	def detail(self) :
		"""To get a detailed view.
		"""
		try :
			return self._detail
		except Exception as e:
			raise e

	@detail.setter
	def detail(self, detail) :
		"""To get a detailed view.
		"""
		try :
			self._detail = detail
		except Exception as e:
			raise e

	@property
	def kernelstate(self) :
		"""Commit status of the PBR6.<br/>Default value: NOTAPPLIED<br/>Possible values = APPLIED, NOTAPPLIED, RE-APPLY, SFAPPLIED, SFNOTAPPLIED.
		"""
		try :
			return self._kernelstate
		except Exception as e:
			raise e

	@property
	def hits(self) :
		"""Number of hits of this PBR6.
		"""
		try :
			return self._hits
		except Exception as e:
			raise e

	@property
	def curstate(self) :
		"""If this route is UP/DOWN.
		"""
		try :
			return self._curstate
		except Exception as e:
			raise e

	@property
	def totalprobes(self) :
		"""The total number of probes sent.
		"""
		try :
			return self._totalprobes
		except Exception as e:
			raise e

	@property
	def totalfailedprobes(self) :
		"""The total number of failed probes.
		"""
		try :
			return self._totalfailedprobes
		except Exception as e:
			raise e

	@property
	def failedprobes(self) :
		"""Number of the current failed monitoring probes.
		"""
		try :
			return self._failedprobes
		except Exception as e:
			raise e

	@property
	def monstatcode(self) :
		"""The code indicating the monitor response.
		"""
		try :
			return self._monstatcode
		except Exception as e:
			raise e

	@property
	def monstatparam1(self) :
		"""First parameter for use with message code.
		"""
		try :
			return self._monstatparam1
		except Exception as e:
			raise e

	@property
	def monstatparam2(self) :
		"""Second parameter for use with message code.
		"""
		try :
			return self._monstatparam2
		except Exception as e:
			raise e

	@property
	def monstatparam3(self) :
		"""Third parameter for use with message code.
		"""
		try :
			return self._monstatparam3
		except Exception as e:
			raise e

	@property
	def data(self) :
		"""Internal data of this route.
		"""
		try :
			return self._data
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(nspbr6_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.nspbr6
		except Exception as e :
			raise e

	def _get_object_name(self) :
		""" Returns the value of object identifier argument
		"""
		try :
			if (self.name) :
				return str(self.name)
			return None
		except Exception as e :
			raise e



	@classmethod
	def add(cls, client, resource) :
		""" Use this API to add nspbr6.
		"""
		try :
			if type(resource) is not list :
				addresource = nspbr6()
				addresource.name = resource.name
				addresource.td = resource.td
				addresource.action = resource.action
				addresource.srcipv6 = resource.srcipv6
				addresource.srcipop = resource.srcipop
				addresource.srcipv6val = resource.srcipv6val
				addresource.srcport = resource.srcport
				addresource.srcportop = resource.srcportop
				addresource.srcportval = resource.srcportval
				addresource.destipv6 = resource.destipv6
				addresource.destipop = resource.destipop
				addresource.destipv6val = resource.destipv6val
				addresource.destport = resource.destport
				addresource.destportop = resource.destportop
				addresource.destportval = resource.destportval
				addresource.srcmac = resource.srcmac
				addresource.protocol = resource.protocol
				addresource.protocolnumber = resource.protocolnumber
				addresource.vlan = resource.vlan
				addresource.vxlan = resource.vxlan
				addresource.Interface = resource.Interface
				addresource.priority = resource.priority
				addresource.state = resource.state
				addresource.msr = resource.msr
				addresource.monitor = resource.monitor
				addresource.nexthop = resource.nexthop
				addresource.nexthopval = resource.nexthopval
				addresource.nexthopvlan = resource.nexthopvlan
				return addresource.add_resource(client)
			else :
				if (resource and len(resource) > 0) :
					addresources = [ nspbr6() for _ in range(len(resource))]
					for i in range(len(resource)) :
						addresources[i].name = resource[i].name
						addresources[i].td = resource[i].td
						addresources[i].action = resource[i].action
						addresources[i].srcipv6 = resource[i].srcipv6
						addresources[i].srcipop = resource[i].srcipop
						addresources[i].srcipv6val = resource[i].srcipv6val
						addresources[i].srcport = resource[i].srcport
						addresources[i].srcportop = resource[i].srcportop
						addresources[i].srcportval = resource[i].srcportval
						addresources[i].destipv6 = resource[i].destipv6
						addresources[i].destipop = resource[i].destipop
						addresources[i].destipv6val = resource[i].destipv6val
						addresources[i].destport = resource[i].destport
						addresources[i].destportop = resource[i].destportop
						addresources[i].destportval = resource[i].destportval
						addresources[i].srcmac = resource[i].srcmac
						addresources[i].protocol = resource[i].protocol
						addresources[i].protocolnumber = resource[i].protocolnumber
						addresources[i].vlan = resource[i].vlan
						addresources[i].vxlan = resource[i].vxlan
						addresources[i].Interface = resource[i].Interface
						addresources[i].priority = resource[i].priority
						addresources[i].state = resource[i].state
						addresources[i].msr = resource[i].msr
						addresources[i].monitor = resource[i].monitor
						addresources[i].nexthop = resource[i].nexthop
						addresources[i].nexthopval = resource[i].nexthopval
						addresources[i].nexthopvlan = resource[i].nexthopvlan
				result = cls.add_bulk_request(client, addresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def renumber(cls, client, resource="") :
		""" Use this API to renumber nspbr6.
		"""
		try :
			if type(resource) is not list :
				renumberresource = nspbr6()
				return renumberresource.perform_operation(client,"renumber")
			else :
				if (resource and len(resource) > 0) :
					renumberresources = [ nspbr6() for _ in range(len(resource))]
				result = cls.perform_operation_bulk_request(client, renumberresources,"renumber")
			return result
		except Exception as e :
			raise e

	@classmethod
	def delete(cls, client, resource) :
		""" Use this API to delete nspbr6.
		"""
		try :
			if type(resource) is not list :
				deleteresource = nspbr6()
				if type(resource) !=  type(deleteresource):
					deleteresource.name = resource
				else :
					deleteresource.name = resource.name
				return deleteresource.delete_resource(client)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						deleteresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						deleteresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i].name
				result = cls.delete_bulk_request(client, deleteresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def update(cls, client, resource) :
		""" Use this API to update nspbr6.
		"""
		try :
			if type(resource) is not list :
				updateresource = nspbr6()
				updateresource.name = resource.name
				updateresource.action = resource.action
				updateresource.srcipv6 = resource.srcipv6
				updateresource.srcipop = resource.srcipop
				updateresource.srcipv6val = resource.srcipv6val
				updateresource.srcport = resource.srcport
				updateresource.srcportop = resource.srcportop
				updateresource.srcportval = resource.srcportval
				updateresource.destipv6 = resource.destipv6
				updateresource.destipop = resource.destipop
				updateresource.destipv6val = resource.destipv6val
				updateresource.destport = resource.destport
				updateresource.destportop = resource.destportop
				updateresource.destportval = resource.destportval
				updateresource.srcmac = resource.srcmac
				updateresource.protocol = resource.protocol
				updateresource.protocolnumber = resource.protocolnumber
				updateresource.vlan = resource.vlan
				updateresource.vxlan = resource.vxlan
				updateresource.Interface = resource.Interface
				updateresource.priority = resource.priority
				updateresource.msr = resource.msr
				updateresource.monitor = resource.monitor
				updateresource.nexthop = resource.nexthop
				updateresource.nexthopval = resource.nexthopval
				updateresource.nexthopvlan = resource.nexthopvlan
				return updateresource.update_resource(client)
			else :
				if (resource and len(resource) > 0) :
					updateresources = [ nspbr6() for _ in range(len(resource))]
					for i in range(len(resource)) :
						updateresources[i].name = resource[i].name
						updateresources[i].action = resource[i].action
						updateresources[i].srcipv6 = resource[i].srcipv6
						updateresources[i].srcipop = resource[i].srcipop
						updateresources[i].srcipv6val = resource[i].srcipv6val
						updateresources[i].srcport = resource[i].srcport
						updateresources[i].srcportop = resource[i].srcportop
						updateresources[i].srcportval = resource[i].srcportval
						updateresources[i].destipv6 = resource[i].destipv6
						updateresources[i].destipop = resource[i].destipop
						updateresources[i].destipv6val = resource[i].destipv6val
						updateresources[i].destport = resource[i].destport
						updateresources[i].destportop = resource[i].destportop
						updateresources[i].destportval = resource[i].destportval
						updateresources[i].srcmac = resource[i].srcmac
						updateresources[i].protocol = resource[i].protocol
						updateresources[i].protocolnumber = resource[i].protocolnumber
						updateresources[i].vlan = resource[i].vlan
						updateresources[i].vxlan = resource[i].vxlan
						updateresources[i].Interface = resource[i].Interface
						updateresources[i].priority = resource[i].priority
						updateresources[i].msr = resource[i].msr
						updateresources[i].monitor = resource[i].monitor
						updateresources[i].nexthop = resource[i].nexthop
						updateresources[i].nexthopval = resource[i].nexthopval
						updateresources[i].nexthopvlan = resource[i].nexthopvlan
				result = cls.update_bulk_request(client, updateresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def unset(cls, client, resource, args) :
		""" Use this API to unset the properties of nspbr6 resource.
		Properties that need to be unset are specified in args array.
		"""
		try :
			if type(resource) is not list :
				unsetresource = nspbr6()
				if type(resource) !=  type(unsetresource):
					unsetresource.name = resource
				else :
					unsetresource.name = resource.name
				return unsetresource.unset_resource(client, args)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						unsetresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						unsetresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i].name
				result = cls.unset_bulk_request(client, unsetresources, args)
			return result
		except Exception as e :
			raise e

	@classmethod
	def enable(cls, client, resource) :
		""" Use this API to enable nspbr6.
		"""
		try :
			if type(resource) is not list :
				enableresource = nspbr6()
				if type(resource) !=  type(enableresource):
					enableresource.name = resource
				else :
					enableresource.name = resource.name
				return enableresource.perform_operation(client,"enable")
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						enableresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							enableresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						enableresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							enableresources[i].name = resource[i].name
				result = cls.perform_operation_bulk_request(client, enableresources,"enable")
			return result
		except Exception as e :
			raise e

	@classmethod
	def disable(cls, client, resource) :
		""" Use this API to disable nspbr6.
		"""
		try :
			if type(resource) is not list :
				disableresource = nspbr6()
				if type(resource) !=  type(disableresource):
					disableresource.name = resource
				else :
					disableresource.name = resource.name
				return disableresource.perform_operation(client,"disable")
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						disableresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							disableresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						disableresources = [ nspbr6() for _ in range(len(resource))]
						for i in range(len(resource)) :
							disableresources[i].name = resource[i].name
				result = cls.perform_operation_bulk_request(client, disableresources,"disable")
			return result
		except Exception as e :
			raise e

	@classmethod
	def clear(cls, client, resource="") :
		""" Use this API to clear nspbr6.
		"""
		try :
			if type(resource) is not list :
				clearresource = nspbr6()
				return clearresource.perform_operation(client,"clear")
			else :
				if (resource and len(resource) > 0) :
					clearresources = [ nspbr6() for _ in range(len(resource))]
				result = cls.perform_operation_bulk_request(client, clearresources,"clear")
			return result
		except Exception as e :
			raise e

	@classmethod
	def apply(cls, client, resource="") :
		""" Use this API to apply nspbr6.
		"""
		try :
			if type(resource) is not list :
				applyresource = nspbr6()
				return applyresource.perform_operation(client,"apply")
			else :
				if (resource and len(resource) > 0) :
					applyresources = [ nspbr6() for _ in range(len(resource))]
				result = cls.perform_operation_bulk_request(client, applyresources,"apply")
			return result
		except Exception as e :
			raise e

	@classmethod
	def get(cls, client, name="", option_="") :
		""" Use this API to fetch all the nspbr6 resources that are configured on netscaler.
		"""
		try :
			if not name :
				obj = nspbr6()
				response = obj.get_resources(client, option_)
			else :
				if type(name) != cls :
					if type(name) is not list :
						obj = nspbr6()
						obj.name = name
						response = obj.get_resource(client, option_)
					else :
						if name and len(name) > 0 :
							response = [nspbr6() for _ in range(len(name))]
							obj = [nspbr6() for _ in range(len(name))]
							for i in range(len(name)) :
								obj[i] = nspbr6()
								obj[i].name = name[i]
								response[i] = obj[i].get_resource(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def get_args(cls, client, args) :
		""" Use this API to fetch all the nspbr6 resources that are configured on netscaler.
	# This uses nspbr6_args which is a way to provide additional arguments while fetching the resources.
		"""
		try :
			obj = nspbr6()
			option_ = options()
			option_.args = nitro_util.object_to_string_withoutquotes(args)
			response = obj.get_resources(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def get_filtered(cls, client, filter_) :
		""" Use this API to fetch filtered set of nspbr6 resources.
		filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = nspbr6()
			option_ = options()
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def count(cls, client) :
		""" Use this API to count the nspbr6 resources configured on NetScaler.
		"""
		try :
			obj = nspbr6()
			option_ = options()
			option_.count = True
			response = obj.get_resources(client, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e :
			raise e

	@classmethod
	def count_filtered(cls, client, filter_) :
		""" Use this API to count filtered the set of nspbr6 resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = nspbr6()
			option_ = options()
			option_.count = True
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e :
			raise e


	class Protocol:
		ICMPV6 = "ICMPV6"
		TCP = "TCP"
		UDP = "UDP"

	class Destipop:
		_EQ = "="
		_NEQ = "!="
		EQ = "EQ"
		NEQ = "NEQ"

	class State:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Kernelstate:
		APPLIED = "APPLIED"
		NOTAPPLIED = "NOTAPPLIED"
		RE_APPLY = "RE-APPLY"
		SFAPPLIED = "SFAPPLIED"
		SFNOTAPPLIED = "SFNOTAPPLIED"

	class Msr:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Srcportop:
		_EQ = "="
		_NEQ = "!="
		EQ = "EQ"
		NEQ = "NEQ"

	class Srcipop:
		_EQ = "="
		_NEQ = "!="
		EQ = "EQ"
		NEQ = "NEQ"

	class Destportop:
		_EQ = "="
		_NEQ = "!="
		EQ = "EQ"
		NEQ = "NEQ"

	class Action:
		ALLOW = "ALLOW"
		DENY = "DENY"

class nspbr6_response(base_response) :
	def __init__(self, length=1) :
		self.nspbr6 = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.nspbr6 = [nspbr6() for _ in range(length)]

