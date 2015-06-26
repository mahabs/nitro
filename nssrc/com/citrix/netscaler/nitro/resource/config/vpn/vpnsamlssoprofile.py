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

class vpnsamlssoprofile(base_resource) :
	""" Configuration for SAML sso action resource. """
	def __init__(self) :
		self._name = ""
		self._samlsigningcertname = ""
		self._assertionconsumerserviceurl = ""
		self._relaystaterule = ""
		self._sendpassword = ""
		self._samlissuername = ""
		self.___count = 0

	@property
	def name(self) :
		"""Name for the new saml single sign-on profile. Must begin with an ASCII alphanumeric or underscore (_) character, and must contain only ASCII alphanumeric, underscore, hash (#), period (.), space, colon (:), at (@), equals (=), and hyphen (-) characters. Cannot be changed after an SSO action is created.
		The following requirement applies only to the NetScaler CLI:
		If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my action" or 'my action').<br/>Minimum length =  1.
		"""
		try :
			return self._name
		except Exception as e:
			raise e

	@name.setter
	def name(self, name) :
		"""Name for the new saml single sign-on profile. Must begin with an ASCII alphanumeric or underscore (_) character, and must contain only ASCII alphanumeric, underscore, hash (#), period (.), space, colon (:), at (@), equals (=), and hyphen (-) characters. Cannot be changed after an SSO action is created.
		The following requirement applies only to the NetScaler CLI:
		If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my action" or 'my action').<br/>Minimum length =  1
		"""
		try :
			self._name = name
		except Exception as e:
			raise e

	@property
	def samlsigningcertname(self) :
		"""Name of the signing authority as given in the SAML server's SSL certificate.<br/>Minimum length =  1.
		"""
		try :
			return self._samlsigningcertname
		except Exception as e:
			raise e

	@samlsigningcertname.setter
	def samlsigningcertname(self, samlsigningcertname) :
		"""Name of the signing authority as given in the SAML server's SSL certificate.<br/>Minimum length =  1
		"""
		try :
			self._samlsigningcertname = samlsigningcertname
		except Exception as e:
			raise e

	@property
	def assertionconsumerserviceurl(self) :
		"""URL to which the assertion is to be sent.<br/>Minimum length =  1.
		"""
		try :
			return self._assertionconsumerserviceurl
		except Exception as e:
			raise e

	@assertionconsumerserviceurl.setter
	def assertionconsumerserviceurl(self, assertionconsumerserviceurl) :
		"""URL to which the assertion is to be sent.<br/>Minimum length =  1
		"""
		try :
			self._assertionconsumerserviceurl = assertionconsumerserviceurl
		except Exception as e:
			raise e

	@property
	def relaystaterule(self) :
		"""Expression to extract relaystate to be sent along with assertion. Evaluation of this expression should return TEXT content. This is typically a target url to which user is redirected after the recipient validates SAML token.
		"""
		try :
			return self._relaystaterule
		except Exception as e:
			raise e

	@relaystaterule.setter
	def relaystaterule(self, relaystaterule) :
		"""Expression to extract relaystate to be sent along with assertion. Evaluation of this expression should return TEXT content. This is typically a target url to which user is redirected after the recipient validates SAML token.
		"""
		try :
			self._relaystaterule = relaystaterule
		except Exception as e:
			raise e

	@property
	def sendpassword(self) :
		"""Option to send password in assertion.<br/>Default value: OFF<br/>Possible values = ON, OFF.
		"""
		try :
			return self._sendpassword
		except Exception as e:
			raise e

	@sendpassword.setter
	def sendpassword(self, sendpassword) :
		"""Option to send password in assertion.<br/>Default value: OFF<br/>Possible values = ON, OFF
		"""
		try :
			self._sendpassword = sendpassword
		except Exception as e:
			raise e

	@property
	def samlissuername(self) :
		"""The name to be used in requests sent from	Netscaler to IdP to uniquely identify Netscaler.<br/>Minimum length =  1.
		"""
		try :
			return self._samlissuername
		except Exception as e:
			raise e

	@samlissuername.setter
	def samlissuername(self, samlissuername) :
		"""The name to be used in requests sent from	Netscaler to IdP to uniquely identify Netscaler.<br/>Minimum length =  1
		"""
		try :
			self._samlissuername = samlissuername
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(vpnsamlssoprofile_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.vpnsamlssoprofile
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
		""" Use this API to add vpnsamlssoprofile.
		"""
		try :
			if type(resource) is not list :
				addresource = vpnsamlssoprofile()
				addresource.name = resource.name
				addresource.samlsigningcertname = resource.samlsigningcertname
				addresource.assertionconsumerserviceurl = resource.assertionconsumerserviceurl
				addresource.relaystaterule = resource.relaystaterule
				addresource.sendpassword = resource.sendpassword
				addresource.samlissuername = resource.samlissuername
				return addresource.add_resource(client)
			else :
				if (resource and len(resource) > 0) :
					addresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
					for i in range(len(resource)) :
						addresources[i].name = resource[i].name
						addresources[i].samlsigningcertname = resource[i].samlsigningcertname
						addresources[i].assertionconsumerserviceurl = resource[i].assertionconsumerserviceurl
						addresources[i].relaystaterule = resource[i].relaystaterule
						addresources[i].sendpassword = resource[i].sendpassword
						addresources[i].samlissuername = resource[i].samlissuername
				result = cls.add_bulk_request(client, addresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def delete(cls, client, resource) :
		""" Use this API to delete vpnsamlssoprofile.
		"""
		try :
			if type(resource) is not list :
				deleteresource = vpnsamlssoprofile()
				if type(resource) !=  type(deleteresource):
					deleteresource.name = resource
				else :
					deleteresource.name = resource.name
				return deleteresource.delete_resource(client)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						deleteresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						deleteresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i].name
				result = cls.delete_bulk_request(client, deleteresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def update(cls, client, resource) :
		""" Use this API to update vpnsamlssoprofile.
		"""
		try :
			if type(resource) is not list :
				updateresource = vpnsamlssoprofile()
				updateresource.name = resource.name
				updateresource.samlsigningcertname = resource.samlsigningcertname
				updateresource.assertionconsumerserviceurl = resource.assertionconsumerserviceurl
				updateresource.sendpassword = resource.sendpassword
				updateresource.samlissuername = resource.samlissuername
				updateresource.relaystaterule = resource.relaystaterule
				return updateresource.update_resource(client)
			else :
				if (resource and len(resource) > 0) :
					updateresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
					for i in range(len(resource)) :
						updateresources[i].name = resource[i].name
						updateresources[i].samlsigningcertname = resource[i].samlsigningcertname
						updateresources[i].assertionconsumerserviceurl = resource[i].assertionconsumerserviceurl
						updateresources[i].sendpassword = resource[i].sendpassword
						updateresources[i].samlissuername = resource[i].samlissuername
						updateresources[i].relaystaterule = resource[i].relaystaterule
				result = cls.update_bulk_request(client, updateresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def unset(cls, client, resource, args) :
		""" Use this API to unset the properties of vpnsamlssoprofile resource.
		Properties that need to be unset are specified in args array.
		"""
		try :
			if type(resource) is not list :
				unsetresource = vpnsamlssoprofile()
				if type(resource) !=  type(unsetresource):
					unsetresource.name = resource
				else :
					unsetresource.name = resource.name
				return unsetresource.unset_resource(client, args)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						unsetresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						unsetresources = [ vpnsamlssoprofile() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i].name
				result = cls.unset_bulk_request(client, unsetresources, args)
			return result
		except Exception as e :
			raise e

	@classmethod
	def get(cls, client, name="", option_="") :
		""" Use this API to fetch all the vpnsamlssoprofile resources that are configured on netscaler.
		"""
		try :
			if not name :
				obj = vpnsamlssoprofile()
				response = obj.get_resources(client, option_)
			else :
				if type(name) != cls :
					if type(name) is not list :
						obj = vpnsamlssoprofile()
						obj.name = name
						response = obj.get_resource(client, option_)
					else :
						if name and len(name) > 0 :
							response = [vpnsamlssoprofile() for _ in range(len(name))]
							obj = [vpnsamlssoprofile() for _ in range(len(name))]
							for i in range(len(name)) :
								obj[i] = vpnsamlssoprofile()
								obj[i].name = name[i]
								response[i] = obj[i].get_resource(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def get_filtered(cls, client, filter_) :
		""" Use this API to fetch filtered set of vpnsamlssoprofile resources.
		filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = vpnsamlssoprofile()
			option_ = options()
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def count(cls, client) :
		""" Use this API to count the vpnsamlssoprofile resources configured on NetScaler.
		"""
		try :
			obj = vpnsamlssoprofile()
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
		""" Use this API to count filtered the set of vpnsamlssoprofile resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = vpnsamlssoprofile()
			option_ = options()
			option_.count = True
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e :
			raise e


	class Sendpassword:
		ON = "ON"
		OFF = "OFF"

class vpnsamlssoprofile_response(base_response) :
	def __init__(self, length=1) :
		self.vpnsamlssoprofile = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.vpnsamlssoprofile = [vpnsamlssoprofile() for _ in range(length)]

