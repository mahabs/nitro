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

class lbsipparameters(base_resource) :
	""" Configuration for SIP parameters resource. """
	def __init__(self) :
		self._rnatsrcport = 0
		self._rnatdstport = 0
		self._retrydur = 0
		self._addrportvip = ""
		self._sip503ratethreshold = 0

	@property
	def rnatsrcport(self) :
		"""Port number with which to match the source port in server-initiated SIP traffic. The rport parameter is added, without a value, to SIP packets that have a matching source port number, and CALL-ID based persistence is implemented for the responses received by the virtual server.<br/>Default value: 0.
		"""
		try :
			return self._rnatsrcport
		except Exception as e:
			raise e

	@rnatsrcport.setter
	def rnatsrcport(self, rnatsrcport) :
		"""Port number with which to match the source port in server-initiated SIP traffic. The rport parameter is added, without a value, to SIP packets that have a matching source port number, and CALL-ID based persistence is implemented for the responses received by the virtual server.<br/>Default value: 0
		"""
		try :
			self._rnatsrcport = rnatsrcport
		except Exception as e:
			raise e

	@property
	def rnatdstport(self) :
		"""Port number with which to match the destination port in server-initiated SIP traffic. The rport parameter is added, without a value, to SIP packets that have a matching source port number, and CALL-ID based persistence is implemented for the responses received by the virtual server.<br/>Default value: 0.
		"""
		try :
			return self._rnatdstport
		except Exception as e:
			raise e

	@rnatdstport.setter
	def rnatdstport(self, rnatdstport) :
		"""Port number with which to match the destination port in server-initiated SIP traffic. The rport parameter is added, without a value, to SIP packets that have a matching source port number, and CALL-ID based persistence is implemented for the responses received by the virtual server.<br/>Default value: 0
		"""
		try :
			self._rnatdstport = rnatdstport
		except Exception as e:
			raise e

	@property
	def retrydur(self) :
		"""Time, in seconds, for which a client must wait before initiating a connection after receiving a 503 Service Unavailable response from the SIP server. The time value is sent in the "Retry-After" header in the 503 response.<br/>Default value: 120<br/>Minimum length =  1.
		"""
		try :
			return self._retrydur
		except Exception as e:
			raise e

	@retrydur.setter
	def retrydur(self, retrydur) :
		"""Time, in seconds, for which a client must wait before initiating a connection after receiving a 503 Service Unavailable response from the SIP server. The time value is sent in the "Retry-After" header in the 503 response.<br/>Default value: 120<br/>Minimum length =  1
		"""
		try :
			self._retrydur = retrydur
		except Exception as e:
			raise e

	@property
	def addrportvip(self) :
		"""Add the rport parameter to the VIA headers of SIP requests that virtual servers receive from clients or servers.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._addrportvip
		except Exception as e:
			raise e

	@addrportvip.setter
	def addrportvip(self, addrportvip) :
		"""Add the rport parameter to the VIA headers of SIP requests that virtual servers receive from clients or servers.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._addrportvip = addrportvip
		except Exception as e:
			raise e

	@property
	def sip503ratethreshold(self) :
		"""Maximum number of 503 Service Unavailable responses to generate, once every 10 milliseconds, when a SIP virtual server becomes unavailable.<br/>Default value: 100.
		"""
		try :
			return self._sip503ratethreshold
		except Exception as e:
			raise e

	@sip503ratethreshold.setter
	def sip503ratethreshold(self, sip503ratethreshold) :
		"""Maximum number of 503 Service Unavailable responses to generate, once every 10 milliseconds, when a SIP virtual server becomes unavailable.<br/>Default value: 100
		"""
		try :
			self._sip503ratethreshold = sip503ratethreshold
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(lbsipparameters_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.lbsipparameters
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
		""" Use this API to update lbsipparameters.
		"""
		try :
			if type(resource) is not list :
				updateresource = lbsipparameters()
				updateresource.rnatsrcport = resource.rnatsrcport
				updateresource.rnatdstport = resource.rnatdstport
				updateresource.retrydur = resource.retrydur
				updateresource.addrportvip = resource.addrportvip
				updateresource.sip503ratethreshold = resource.sip503ratethreshold
				return updateresource.update_resource(client)
		except Exception as e :
			raise e

	@classmethod
	def unset(cls, client, resource, args) :
		""" Use this API to unset the properties of lbsipparameters resource.
		Properties that need to be unset are specified in args array.
		"""
		try :
			if type(resource) is not list :
				unsetresource = lbsipparameters()
				return unsetresource.unset_resource(client, args)
		except Exception as e :
			raise e

	@classmethod
	def get(cls, client, name="", option_="") :
		""" Use this API to fetch all the lbsipparameters resources that are configured on netscaler.
		"""
		try :
			if not name :
				obj = lbsipparameters()
				response = obj.get_resources(client, option_)
			return response
		except Exception as e :
			raise e


	class Addrportvip:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

class lbsipparameters_response(base_response) :
	def __init__(self, length=1) :
		self.lbsipparameters = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.lbsipparameters = [lbsipparameters() for _ in range(length)]

