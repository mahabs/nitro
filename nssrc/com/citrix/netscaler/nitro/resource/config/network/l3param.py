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

class l3param(base_resource) :
	""" Configuration for Layer 3 related parameter resource. """
	def __init__(self) :
		self._srcnat = ""
		self._icmpgenratethreshold = 0
		self._overridernat = ""
		self._dropdfflag = ""
		self._miproundrobin = ""
		self._externalloopback = ""
		self._tnlpmtuwoconn = ""
		self._usipserverstraypkt = ""
		self._forwardicmpfragments = ""
		self._dropipfragments = ""
		self._acllogtime = 0
		self._icmperrgenerate = ""

	@property
	def srcnat(self) :
		"""Perform NAT if only the source is in the private network.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._srcnat
		except Exception as e:
			raise e

	@srcnat.setter
	def srcnat(self, srcnat) :
		"""Perform NAT if only the source is in the private network.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._srcnat = srcnat
		except Exception as e:
			raise e

	@property
	def icmpgenratethreshold(self) :
		"""NS generated ICMP pkts per 10ms rate threshold.<br/>Default value: 100.
		"""
		try :
			return self._icmpgenratethreshold
		except Exception as e:
			raise e

	@icmpgenratethreshold.setter
	def icmpgenratethreshold(self, icmpgenratethreshold) :
		"""NS generated ICMP pkts per 10ms rate threshold.<br/>Default value: 100
		"""
		try :
			self._icmpgenratethreshold = icmpgenratethreshold
		except Exception as e:
			raise e

	@property
	def overridernat(self) :
		"""USNIP/USIP settings override RNAT settings for configured
		service/virtual server traffic.. .<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._overridernat
		except Exception as e:
			raise e

	@overridernat.setter
	def overridernat(self, overridernat) :
		"""USNIP/USIP settings override RNAT settings for configured
		service/virtual server traffic.. .<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._overridernat = overridernat
		except Exception as e:
			raise e

	@property
	def dropdfflag(self) :
		"""Enable dropping the IP DF flag.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._dropdfflag
		except Exception as e:
			raise e

	@dropdfflag.setter
	def dropdfflag(self, dropdfflag) :
		"""Enable dropping the IP DF flag.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._dropdfflag = dropdfflag
		except Exception as e:
			raise e

	@property
	def miproundrobin(self) :
		"""Enable round robin usage of mapped IPs.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._miproundrobin
		except Exception as e:
			raise e

	@miproundrobin.setter
	def miproundrobin(self, miproundrobin) :
		"""Enable round robin usage of mapped IPs.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._miproundrobin = miproundrobin
		except Exception as e:
			raise e

	@property
	def externalloopback(self) :
		"""Enable external loopback.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._externalloopback
		except Exception as e:
			raise e

	@externalloopback.setter
	def externalloopback(self, externalloopback) :
		"""Enable external loopback.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._externalloopback = externalloopback
		except Exception as e:
			raise e

	@property
	def tnlpmtuwoconn(self) :
		"""Enable external loopback.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._tnlpmtuwoconn
		except Exception as e:
			raise e

	@tnlpmtuwoconn.setter
	def tnlpmtuwoconn(self, tnlpmtuwoconn) :
		"""Enable external loopback.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._tnlpmtuwoconn = tnlpmtuwoconn
		except Exception as e:
			raise e

	@property
	def usipserverstraypkt(self) :
		"""Enable detection of stray server side pkts in USIP mode.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._usipserverstraypkt
		except Exception as e:
			raise e

	@usipserverstraypkt.setter
	def usipserverstraypkt(self, usipserverstraypkt) :
		"""Enable detection of stray server side pkts in USIP mode.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._usipserverstraypkt = usipserverstraypkt
		except Exception as e:
			raise e

	@property
	def forwardicmpfragments(self) :
		"""Enable forwarding of ICMP fragments.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._forwardicmpfragments
		except Exception as e:
			raise e

	@forwardicmpfragments.setter
	def forwardicmpfragments(self, forwardicmpfragments) :
		"""Enable forwarding of ICMP fragments.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._forwardicmpfragments = forwardicmpfragments
		except Exception as e:
			raise e

	@property
	def dropipfragments(self) :
		"""Enable dropping of IP fragments.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._dropipfragments
		except Exception as e:
			raise e

	@dropipfragments.setter
	def dropipfragments(self, dropipfragments) :
		"""Enable dropping of IP fragments.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._dropipfragments = dropipfragments
		except Exception as e:
			raise e

	@property
	def acllogtime(self) :
		"""Parameter to tune acl logging time.<br/>Default value: 5000.
		"""
		try :
			return self._acllogtime
		except Exception as e:
			raise e

	@acllogtime.setter
	def acllogtime(self, acllogtime) :
		"""Parameter to tune acl logging time.<br/>Default value: 5000
		"""
		try :
			self._acllogtime = acllogtime
		except Exception as e:
			raise e

	@property
	def icmperrgenerate(self) :
		"""Enable/Disable fragmentation required icmp error generation, before encapsulating a packet with vPath header. This knob is only functional for vPath Environment.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._icmperrgenerate
		except Exception as e:
			raise e

	@icmperrgenerate.setter
	def icmperrgenerate(self, icmperrgenerate) :
		"""Enable/Disable fragmentation required icmp error generation, before encapsulating a packet with vPath header. This knob is only functional for vPath Environment.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._icmperrgenerate = icmperrgenerate
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(l3param_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.l3param
		except Exception as e :
			raise e

	def _get_object_name(self) :
		""" Returns the value of object identifier argument
		"""
		try :
			return None
		except Exception as e :
			raise e



	@classmethod
	def update(cls, client, resource) :
		""" Use this API to update l3param.
		"""
		try :
			if type(resource) is not list :
				updateresource = l3param()
				updateresource.srcnat = resource.srcnat
				updateresource.icmpgenratethreshold = resource.icmpgenratethreshold
				updateresource.overridernat = resource.overridernat
				updateresource.dropdfflag = resource.dropdfflag
				updateresource.miproundrobin = resource.miproundrobin
				updateresource.externalloopback = resource.externalloopback
				updateresource.tnlpmtuwoconn = resource.tnlpmtuwoconn
				updateresource.usipserverstraypkt = resource.usipserverstraypkt
				updateresource.forwardicmpfragments = resource.forwardicmpfragments
				updateresource.dropipfragments = resource.dropipfragments
				updateresource.acllogtime = resource.acllogtime
				updateresource.icmperrgenerate = resource.icmperrgenerate
				return updateresource.update_resource(client)
		except Exception as e :
			raise e

	@classmethod
	def unset(cls, client, resource, args) :
		""" Use this API to unset the properties of l3param resource.
		Properties that need to be unset are specified in args array.
		"""
		try :
			if type(resource) is not list :
				unsetresource = l3param()
				return unsetresource.unset_resource(client, args)
		except Exception as e :
			raise e

	@classmethod
	def get(cls, client, name="", option_="") :
		""" Use this API to fetch all the l3param resources that are configured on netscaler.
		"""
		try :
			if not name :
				obj = l3param()
				response = obj.get_resources(client, option_)
			return response
		except Exception as e :
			raise e


	class Icmperrgenerate:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Dropipfragments:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Overridernat:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Tnlpmtuwoconn:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Usipserverstraypkt:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Srcnat:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Externalloopback:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Forwardicmpfragments:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Dropdfflag:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Miproundrobin:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

class l3param_response(base_response) :
	def __init__(self, length=1) :
		self.l3param = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.l3param = [l3param() for _ in range(length)]

