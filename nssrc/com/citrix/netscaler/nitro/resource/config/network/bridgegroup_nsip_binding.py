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

class bridgegroup_nsip_binding(base_resource) :
	""" Binding class showing the nsip that can be bound to bridgegroup.
	"""
	def __init__(self) :
		self._ipaddress = ""
		self._td = 0
		self._netmask = ""
		self._rnat = False
		self._id = 0
		self.___count = 0

	@property
	def id(self) :
		"""The integer that uniquely identifies the bridge group.<br/>Minimum value =  1<br/>Maximum value =  1000.
		"""
		try :
			return self._id
		except Exception as e:
			raise e

	@id.setter
	def id(self, id) :
		"""The integer that uniquely identifies the bridge group.<br/>Minimum value =  1<br/>Maximum value =  1000
		"""
		try :
			self._id = id
		except Exception as e:
			raise e

	@property
	def td(self) :
		"""Integer value that uniquely identifies the traffic domain in which you want to configure the entity. If you do not specify an ID, the entity becomes part of the default traffic domain, which has an ID of 0.<br/>Minimum value =  0<br/>Maximum value =  4094.
		"""
		try :
			return self._td
		except Exception as e:
			raise e

	@td.setter
	def td(self, td) :
		"""Integer value that uniquely identifies the traffic domain in which you want to configure the entity. If you do not specify an ID, the entity becomes part of the default traffic domain, which has an ID of 0.<br/>Minimum value =  0<br/>Maximum value =  4094
		"""
		try :
			self._td = td
		except Exception as e:
			raise e

	@property
	def netmask(self) :
		"""The network mask for the subnet defined for the bridge group.
		"""
		try :
			return self._netmask
		except Exception as e:
			raise e

	@netmask.setter
	def netmask(self, netmask) :
		"""The network mask for the subnet defined for the bridge group.
		"""
		try :
			self._netmask = netmask
		except Exception as e:
			raise e

	@property
	def ipaddress(self) :
		"""The IP address assigned to the  bridge group.
		"""
		try :
			return self._ipaddress
		except Exception as e:
			raise e

	@ipaddress.setter
	def ipaddress(self, ipaddress) :
		"""The IP address assigned to the  bridge group.
		"""
		try :
			self._ipaddress = ipaddress
		except Exception as e:
			raise e

	@property
	def rnat(self) :
		"""Temporary flag used for internal purpose.
		"""
		try :
			return self._rnat
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(bridgegroup_nsip_binding_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.bridgegroup_nsip_binding
		except Exception as e :
			raise e

	def _get_object_name(self) :
		""" Returns the value of object identifier argument
		"""
		try :
			if (self.id) :
				return str(self.id)
			return None
		except Exception as e :
			raise e



	@classmethod
	def add(cls, client, resource) :
		try :
			if resource and type(resource) is not list :
				updateresource = bridgegroup_nsip_binding()
				updateresource.ipaddress = resource.ipaddress
				updateresource.netmask = resource.netmask
				return updateresource.update_resource(client)
			else :
				if resource and len(resource) > 0 :
					updateresources = [bridgegroup_nsip_binding() for _ in range(len(resource))]
					for i in range(len(resource)) :
						updateresources[i].ipaddress = resource[i].ipaddress
						updateresources[i].netmask = resource[i].netmask
				return cls.update_bulk_request(client, updateresources)
		except Exception as e :
			raise e

	@classmethod
	def delete(cls, client, resource) :
		try :
			if resource and type(resource) is not list :
				deleteresource = bridgegroup_nsip_binding()
				deleteresource.ipaddress = resource.ipaddress
				deleteresource.netmask = resource.netmask
				return deleteresource.delete_resource(client)
			else :
				if resource and len(resource) > 0 :
					deleteresources = [bridgegroup_nsip_binding() for _ in range(len(resource))]
					for i in range(len(resource)) :
						deleteresources[i].ipaddress = resource[i].ipaddress
						deleteresources[i].netmask = resource[i].netmask
				return cls.delete_bulk_request(client, deleteresources)
		except Exception as e :
			raise e

	@classmethod
	def get(cls, service, id) :
		""" Use this API to fetch bridgegroup_nsip_binding resources.
		"""
		try :
			obj = bridgegroup_nsip_binding()
			obj.id = id
			response = obj.get_resources(service)
			return response
		except Exception as e:
			raise e

	@classmethod
	def get_filtered(cls, service, id, filter_) :
		""" Use this API to fetch filtered set of bridgegroup_nsip_binding resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = bridgegroup_nsip_binding()
			obj.id = id
			option_ = options()
			option_.filter = filter_
			response = obj.getfiltered(service, option_)
			return response
		except Exception as e:
			raise e

	@classmethod
	def count(cls, service, id) :
		""" Use this API to count bridgegroup_nsip_binding resources configued on NetScaler.
		"""
		try :
			obj = bridgegroup_nsip_binding()
			obj.id = id
			option_ = options()
			option_.count = True
			response = obj.get_resources(service, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e:
			raise e

	@classmethod
	def count_filtered(cls, service, id, filter_) :
		""" Use this API to count the filtered set of bridgegroup_nsip_binding resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = bridgegroup_nsip_binding()
			obj.id = id
			option_ = options()
			option_.count = True
			option_.filter = filter_
			response = obj.getfiltered(service, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e:
			raise e

class bridgegroup_nsip_binding_response(base_response) :
	def __init__(self, length=1) :
		self.bridgegroup_nsip_binding = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.bridgegroup_nsip_binding = [bridgegroup_nsip_binding() for _ in range(length)]

