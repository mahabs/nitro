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

class lbvserver_service_binding(base_resource) :
	""" Binding class showing the service that can be bound to lbvserver.
	"""
	def __init__(self) :
		self._servicename = ""
		self._ipv46 = ""
		self._port = 0
		self._servicetype = ""
		self._curstate = ""
		self._weight = 0
		self._dynamicweight = 0
		self._cookieipport = ""
		self._vserverid = ""
		self._vsvrbindsvcip = ""
		self._vsvrbindsvcport = 0
		self._name = ""
		self._servicegroupname = ""
		self.___count = 0

	@property
	def weight(self) :
		"""Weight to assign to the specified service.<br/>Minimum value =  1<br/>Maximum value =  100.
		"""
		try :
			return self._weight
		except Exception as e:
			raise e

	@weight.setter
	def weight(self, weight) :
		"""Weight to assign to the specified service.<br/>Minimum value =  1<br/>Maximum value =  100
		"""
		try :
			self._weight = weight
		except Exception as e:
			raise e

	@property
	def name(self) :
		"""Name for the virtual server. Must begin with an ASCII alphanumeric or underscore (_) character, and must contain only ASCII alphanumeric, underscore, hash (#), period (.), space, colon (:), at sign (@), equal sign (=), and hyphen (-) characters. Can be changed after the virtual server is created.
		CLI Users: If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my vserver" or 'my vserver'). .<br/>Minimum length =  1.
		"""
		try :
			return self._name
		except Exception as e:
			raise e

	@name.setter
	def name(self, name) :
		"""Name for the virtual server. Must begin with an ASCII alphanumeric or underscore (_) character, and must contain only ASCII alphanumeric, underscore, hash (#), period (.), space, colon (:), at sign (@), equal sign (=), and hyphen (-) characters. Can be changed after the virtual server is created.
		CLI Users: If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my vserver" or 'my vserver'). .<br/>Minimum length =  1
		"""
		try :
			self._name = name
		except Exception as e:
			raise e

	@property
	def servicename(self) :
		"""Service to bind to the virtual server.<br/>Minimum length =  1.
		"""
		try :
			return self._servicename
		except Exception as e:
			raise e

	@servicename.setter
	def servicename(self, servicename) :
		"""Service to bind to the virtual server.<br/>Minimum length =  1
		"""
		try :
			self._servicename = servicename
		except Exception as e:
			raise e

	@property
	def servicegroupname(self) :
		try :
			return self._servicegroupname
		except Exception as e:
			raise e

	@servicegroupname.setter
	def servicegroupname(self, servicegroupname) :
		try :
			self._servicegroupname = servicegroupname
		except Exception as e:
			raise e

	@property
	def cookieipport(self) :
		"""Encryped Ip address and port of the service that is inserted into the set-cookie http header.
		"""
		try :
			return self._cookieipport
		except Exception as e:
			raise e

	@property
	def port(self) :
		"""Port number for the virtual server.<br/>Range 1 - 65535.
		"""
		try :
			return self._port
		except Exception as e:
			raise e

	@property
	def vsvrbindsvcport(self) :
		"""used for showing ports of bound entities.<br/>Range 1 - 65535.
		"""
		try :
			return self._vsvrbindsvcport
		except Exception as e:
			raise e

	@property
	def curstate(self) :
		"""Current LB vserver state.<br/>Possible values = UP, DOWN, UNKNOWN, BUSY, OUT OF SERVICE, GOING OUT OF SERVICE, DOWN WHEN GOING OUT OF SERVICE, NS_EMPTY_STR, Unknown, DISABLED.
		"""
		try :
			return self._curstate
		except Exception as e:
			raise e

	@property
	def vserverid(self) :
		"""Vserver Id.
		"""
		try :
			return self._vserverid
		except Exception as e:
			raise e

	@property
	def ipv46(self) :
		"""IPv4 or IPv6 address to assign to the virtual server.
		"""
		try :
			return self._ipv46
		except Exception as e:
			raise e

	@property
	def dynamicweight(self) :
		"""Dynamic weight.
		"""
		try :
			return self._dynamicweight
		except Exception as e:
			raise e

	@property
	def vsvrbindsvcip(self) :
		"""used for showing the ip of bound entities.
		"""
		try :
			return self._vsvrbindsvcip
		except Exception as e:
			raise e

	@property
	def servicetype(self) :
		"""Protocol used by the service (also called the service type).<br/>Possible values = HTTP, FTP, TCP, UDP, SSL, SSL_BRIDGE, SSL_TCP, DTLS, NNTP, DNS, DHCPRA, ANY, SIP_UDP, DNS_TCP, RTSP, PUSH, SSL_PUSH, RADIUS, RDP, MYSQL, MSSQL, DIAMETER, SSL_DIAMETER, TFTP, ORACLE.
		"""
		try :
			return self._servicetype
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(lbvserver_service_binding_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.lbvserver_service_binding
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
		try :
			if resource and type(resource) is not list :
				updateresource = lbvserver_service_binding()
				updateresource.name = resource.name
				updateresource.servicename = resource.servicename
				updateresource.servicegroupname = resource.servicegroupname
				return updateresource.update_resource(client)
			else :
				if resource and len(resource) > 0 :
					updateresources = [lbvserver_service_binding() for _ in range(len(resource))]
					for i in range(len(resource)) :
						updateresources[i].name = resource[i].name
						updateresources[i].servicename = resource[i].servicename
						updateresources[i].servicegroupname = resource[i].servicegroupname
				return cls.update_bulk_request(client, updateresources)
		except Exception as e :
			raise e

	@classmethod
	def delete(cls, client, resource) :
		try :
			if resource and type(resource) is not list :
				deleteresource = lbvserver_service_binding()
				deleteresource.name = resource.name
				deleteresource.servicename = resource.servicename
				deleteresource.servicegroupname = resource.servicegroupname
				return deleteresource.delete_resource(client)
			else :
				if resource and len(resource) > 0 :
					deleteresources = [lbvserver_service_binding() for _ in range(len(resource))]
					for i in range(len(resource)) :
						deleteresources[i].name = resource[i].name
						deleteresources[i].servicename = resource[i].servicename
						deleteresources[i].servicegroupname = resource[i].servicegroupname
				return cls.delete_bulk_request(client, deleteresources)
		except Exception as e :
			raise e

	@classmethod
	def get(cls, service, name) :
		""" Use this API to fetch lbvserver_service_binding resources.
		"""
		try :
			obj = lbvserver_service_binding()
			obj.name = name
			response = obj.get_resources(service)
			return response
		except Exception as e:
			raise e

	@classmethod
	def get_filtered(cls, service, name, filter_) :
		""" Use this API to fetch filtered set of lbvserver_service_binding resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = lbvserver_service_binding()
			obj.name = name
			option_ = options()
			option_.filter = filter_
			response = obj.getfiltered(service, option_)
			return response
		except Exception as e:
			raise e

	@classmethod
	def count(cls, service, name) :
		""" Use this API to count lbvserver_service_binding resources configued on NetScaler.
		"""
		try :
			obj = lbvserver_service_binding()
			obj.name = name
			option_ = options()
			option_.count = True
			response = obj.get_resources(service, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e:
			raise e

	@classmethod
	def count_filtered(cls, service, name, filter_) :
		""" Use this API to count the filtered set of lbvserver_service_binding resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = lbvserver_service_binding()
			obj.name = name
			option_ = options()
			option_.count = True
			option_.filter = filter_
			response = obj.getfiltered(service, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e:
			raise e

	class Servicetype:
		HTTP = "HTTP"
		FTP = "FTP"
		TCP = "TCP"
		UDP = "UDP"
		SSL = "SSL"
		SSL_BRIDGE = "SSL_BRIDGE"
		SSL_TCP = "SSL_TCP"
		DTLS = "DTLS"
		NNTP = "NNTP"
		DNS = "DNS"
		DHCPRA = "DHCPRA"
		ANY = "ANY"
		SIP_UDP = "SIP_UDP"
		DNS_TCP = "DNS_TCP"
		RTSP = "RTSP"
		PUSH = "PUSH"
		SSL_PUSH = "SSL_PUSH"
		RADIUS = "RADIUS"
		RDP = "RDP"
		MYSQL = "MYSQL"
		MSSQL = "MSSQL"
		DIAMETER = "DIAMETER"
		SSL_DIAMETER = "SSL_DIAMETER"
		TFTP = "TFTP"
		ORACLE = "ORACLE"

	class Bindpoint:
		REQUEST = "REQUEST"
		RESPONSE = "RESPONSE"

	class Labeltype:
		reqvserver = "reqvserver"
		resvserver = "resvserver"
		policylabel = "policylabel"

	class Curstate:
		UP = "UP"
		DOWN = "DOWN"
		UNKNOWN = "UNKNOWN"
		BUSY = "BUSY"
		OUT_OF_SERVICE = "OUT OF SERVICE"
		GOING_OUT_OF_SERVICE = "GOING OUT OF SERVICE"
		DOWN_WHEN_GOING_OUT_OF_SERVICE = "DOWN WHEN GOING OUT OF SERVICE"
		NS_EMPTY_STR = "NS_EMPTY_STR"
		Unknown = "Unknown"
		DISABLED = "DISABLED"

class lbvserver_service_binding_response(base_response) :
	def __init__(self, length=1) :
		self.lbvserver_service_binding = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.lbvserver_service_binding = [lbvserver_service_binding() for _ in range(length)]

