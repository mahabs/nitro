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

class appfwprofile_stats(base_resource) :
	""" Statistics for application firewall profile resource.
	"""
	def __init__(self) :
		self._name = ""
		self._clearstats = ""
		self._appfirewallrequestsperprofile = 0
		self._appfirewallrequestsperprofilerate = 0
		self._appfirewallreqbytesperprofile = 0
		self._appfirewallreqbytesperprofilerate = 0
		self._appfirewallresponsesperprofile = 0
		self._appfirewallresponsesperprofilerate = 0
		self._appfirewallresbytesperprofile = 0
		self._appfirewallresbytesperprofilerate = 0
		self._appfirewallabortsperprofile = 0
		self._appfirewallabortsperprofilerate = 0
		self._appfirewallredirectsperprofile = 0
		self._appfirewallredirectsperprofilerate = 0
		self._appfirewalllongavgresptimeperprofile = 0
		self._appfirewallshortavgresptimeperprofile = 0
		self._appfirewallviolstarturlperprofile = 0
		self._appfirewallviolstarturlperprofilerate = 0
		self._appfirewallvioldenyurlperprofile = 0
		self._appfirewallvioldenyurlperprofilerate = 0
		self._appfirewallviolrefererheaderperprofile = 0
		self._appfirewallviolrefererheaderperprofilerate = 0
		self._appfirewallviolbufferoverflowperprofile = 0
		self._appfirewallviolbufferoverflowperprofilerate = 0
		self._appfirewallviolcookieperprofile = 0
		self._appfirewallviolcookieperprofilerate = 0
		self._appfirewallviolcsrftagperprofile = 0
		self._appfirewallviolcsrftagperprofilerate = 0
		self._appfirewallviolxssperprofile = 0
		self._appfirewallviolxssperprofilerate = 0
		self._appfirewallviolsqlperprofile = 0
		self._appfirewallviolsqlperprofilerate = 0
		self._appfirewallviolfieldformatperprofile = 0
		self._appfirewallviolfieldformatperprofilerate = 0
		self._appfirewallviolfieldconsistencyperprofile = 0
		self._appfirewallviolfieldconsistencyperprofilerate = 0
		self._appfirewallviolcreditcardperprofile = 0
		self._appfirewallviolcreditcardperprofilerate = 0
		self._appfirewallviolsafeobjectperprofile = 0
		self._appfirewallviolsafeobjectperprofilerate = 0
		self._appfirewallviolsignatureperprofile = 0
		self._appfirewallviolsignatureperprofilerate = 0
		self._appfirewallviolwellformednessviolationsperprofile = 0
		self._appfirewallviolwellformednessviolationsperprofilerate = 0
		self._appfirewallviolxdosviolationsperprofile = 0
		self._appfirewallviolxdosviolationsperprofilerate = 0
		self._appfirewallviolmsgvalviolationsperprofile = 0
		self._appfirewallviolmsgvalviolationsperprofilerate = 0
		self._appfirewallviolwsiviolationsperprofile = 0
		self._appfirewallviolwsiviolationsperprofilerate = 0
		self._appfirewallviolxmlsqlviolationsperprofile = 0
		self._appfirewallviolxmlsqlviolationsperprofilerate = 0
		self._appfirewallviolxmlxssviolationsperprofile = 0
		self._appfirewallviolxmlxssviolationsperprofilerate = 0
		self._appfirewallviolxmlattachmentviolationsperprofile = 0
		self._appfirewallviolxmlattachmentviolationsperprofilerate = 0
		self._appfirewallviolxmlsoapfaultviolationsperprofile = 0
		self._appfirewallviolxmlsoapfaultviolationsperprofilerate = 0
		self._appfirewallviolxmlgenericviolationsperprofile = 0
		self._appfirewallviolxmlgenericviolationsperprofilerate = 0
		self._appfirewalltotalviolperprofile = 0
		self._appfirewallviolperprofilerate = 0
		self._appfirewallret4xxperprofile = 0
		self._appfirewallret4xxperprofilerate = 0
		self._appfirewallret5xxperprofile = 0
		self._appfirewallret5xxperprofilerate = 0

	@property
	def name(self) :
		"""Name of the application firewall profile.<br/>Minimum length =  1.
		"""
		try :
			return self._name
		except Exception as e:
			raise e

	@name.setter
	def name(self, name) :
		"""Name of the application firewall profile.
		"""
		try :
			self._name = name
		except Exception as e:
			raise e

	@property
	def clearstats(self) :
		"""Clear the statsistics / counters.<br/>Possible values = basic, full.
		"""
		try :
			return self._clearstats
		except Exception as e:
			raise e

	@clearstats.setter
	def clearstats(self, clearstats) :
		"""Clear the statsistics / counters
		"""
		try :
			self._clearstats = clearstats
		except Exception as e:
			raise e

	@property
	def appfirewallviolmsgvalviolationsperprofile(self) :
		"""Number of XML Message Validation security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolmsgvalviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolperprofilerate(self) :
		"""Rate (/s) counter for appfirewalltotalviolperprofile.
		"""
		try :
			return self._appfirewallviolperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolstarturlperprofile(self) :
		"""Number of Start URL security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolstarturlperprofile
		except Exception as e:
			raise e

	@property
	def appfirewalltotalviolperprofile(self) :
		"""Number of violations seen by the application firewall on per profile basis.
		"""
		try :
			return self._appfirewalltotalviolperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallret5xxperprofile(self) :
		"""Number of requests returning HTTP 5xx from the backend server.
		"""
		try :
			return self._appfirewallret5xxperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallredirectsperprofile(self) :
		"""HTTP/HTTPS requests redirected by the Application Firewall to a different Web page or web server. (HTTP 302).
		"""
		try :
			return self._appfirewallredirectsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallresponsesperprofile(self) :
		"""HTTP/HTTPS responses sent by your protected web servers via the Application Firewall.
		"""
		try :
			return self._appfirewallresponsesperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallrequestsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallrequestsperprofile.
		"""
		try :
			return self._appfirewallrequestsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlsoapfaultviolationsperprofile(self) :
		"""Number of requests returning soap:fault from the backend server.
		"""
		try :
			return self._appfirewallviolxmlsoapfaultviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolwsiviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolwsiviolationsperprofile.
		"""
		try :
			return self._appfirewallviolwsiviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolwellformednessviolationsperprofile(self) :
		"""Number of XML Format security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolwellformednessviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolfieldformatperprofile(self) :
		"""Number of Field Format security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolfieldformatperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolcookieperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolcookieperprofile.
		"""
		try :
			return self._appfirewallviolcookieperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallresbytesperprofilerate(self) :
		"""Rate (/s) counter for appfirewallresbytesperprofile.
		"""
		try :
			return self._appfirewallresbytesperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolcreditcardperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolcreditcardperprofile.
		"""
		try :
			return self._appfirewallviolcreditcardperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallresbytesperprofile(self) :
		"""Number of bytes transfered for responses.
		"""
		try :
			return self._appfirewallresbytesperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxssperprofile(self) :
		"""Number of HTML Cross-Site Scripting security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolxssperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlsoapfaultviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxmlsoapfaultviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxmlsoapfaultviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallreqbytesperprofilerate(self) :
		"""Rate (/s) counter for appfirewallreqbytesperprofile.
		"""
		try :
			return self._appfirewallreqbytesperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolmsgvalviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolmsgvalviolationsperprofile.
		"""
		try :
			return self._appfirewallviolmsgvalviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolfieldconsistencyperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolfieldconsistencyperprofile.
		"""
		try :
			return self._appfirewallviolfieldconsistencyperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlxssviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxmlxssviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxmlxssviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallrequestsperprofile(self) :
		"""HTTP/HTTPS requests sent to your protected web servers via the Application Firewall.
		"""
		try :
			return self._appfirewallrequestsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolsignatureperprofile(self) :
		"""Number of Signature violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolsignatureperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlattachmentviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxmlattachmentviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxmlattachmentviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolsqlperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolsqlperprofile.
		"""
		try :
			return self._appfirewallviolsqlperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolcsrftagperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolcsrftagperprofile.
		"""
		try :
			return self._appfirewallviolcsrftagperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolstarturlperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolstarturlperprofile.
		"""
		try :
			return self._appfirewallviolstarturlperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlsqlviolationsperprofile(self) :
		"""Number of XML SQL Injection security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolxmlsqlviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallvioldenyurlperprofile(self) :
		"""Number of Deny URL security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallvioldenyurlperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallredirectsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallredirectsperprofile.
		"""
		try :
			return self._appfirewallredirectsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolcsrftagperprofile(self) :
		"""Number of Cross Site Request Forgery form tag security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolcsrftagperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolwsiviolationsperprofile(self) :
		"""Number of Web Services Interoperability (WS-I) security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolwsiviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallshortavgresptimeperprofile(self) :
		"""Average backend response time in milliseconds over the last 7 seconds.
		"""
		try :
			return self._appfirewallshortavgresptimeperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolsafeobjectperprofile(self) :
		"""Number of Safe Object security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolsafeobjectperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallresponsesperprofilerate(self) :
		"""Rate (/s) counter for appfirewallresponsesperprofile.
		"""
		try :
			return self._appfirewallresponsesperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolrefererheaderperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolrefererheaderperprofile.
		"""
		try :
			return self._appfirewallviolrefererheaderperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallvioldenyurlperprofilerate(self) :
		"""Rate (/s) counter for appfirewallvioldenyurlperprofile.
		"""
		try :
			return self._appfirewallvioldenyurlperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallabortsperprofile(self) :
		"""Incomplete HTTP/HTTPS requests aborted by the client before the Application Firewall could finish processing them.
		"""
		try :
			return self._appfirewallabortsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolcookieperprofile(self) :
		"""Number of Cookie Consistency security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolcookieperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallret4xxperprofile(self) :
		"""Number of requests returning HTTP 4xx from the backend server.
		"""
		try :
			return self._appfirewallret4xxperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolfieldformatperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolfieldformatperprofile.
		"""
		try :
			return self._appfirewallviolfieldformatperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolbufferoverflowperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolbufferoverflowperprofile.
		"""
		try :
			return self._appfirewallviolbufferoverflowperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolsqlperprofile(self) :
		"""Number of HTML SQL Injection security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolsqlperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxssperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxssperprofile.
		"""
		try :
			return self._appfirewallviolxssperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolcreditcardperprofile(self) :
		"""Number of Credit Card security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolcreditcardperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolfieldconsistencyperprofile(self) :
		"""Number of Field Consistency security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolfieldconsistencyperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallret4xxperprofilerate(self) :
		"""Rate (/s) counter for appfirewallret4xxperprofile.
		"""
		try :
			return self._appfirewallret4xxperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolsafeobjectperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolsafeobjectperprofile.
		"""
		try :
			return self._appfirewallviolsafeobjectperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlgenericviolationsperprofile(self) :
		"""Number of requests returning XML generic violation from the backend server.
		"""
		try :
			return self._appfirewallviolxmlgenericviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolsignatureperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolsignatureperprofile.
		"""
		try :
			return self._appfirewallviolsignatureperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewalllongavgresptimeperprofile(self) :
		"""Average backend response time in milliseconds since reboot.
		"""
		try :
			return self._appfirewalllongavgresptimeperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallabortsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallabortsperprofile.
		"""
		try :
			return self._appfirewallabortsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolbufferoverflowperprofile(self) :
		"""Number of Buffer Overflow security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolbufferoverflowperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlsqlviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxmlsqlviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxmlsqlviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallreqbytesperprofile(self) :
		"""Number of bytes transfered for requests.
		"""
		try :
			return self._appfirewallreqbytesperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlgenericviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxmlgenericviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxmlgenericviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlattachmentviolationsperprofile(self) :
		"""Number of XML Attachment security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolxmlattachmentviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxdosviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolxdosviolationsperprofile.
		"""
		try :
			return self._appfirewallviolxdosviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolwellformednessviolationsperprofilerate(self) :
		"""Rate (/s) counter for appfirewallviolwellformednessviolationsperprofile.
		"""
		try :
			return self._appfirewallviolwellformednessviolationsperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolxdosviolationsperprofile(self) :
		"""Number of XML Denial-of-Service security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolxdosviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallviolxmlxssviolationsperprofile(self) :
		"""Number of XML Cross-Site Scripting (XSS) security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolxmlxssviolationsperprofile
		except Exception as e:
			raise e

	@property
	def appfirewallret5xxperprofilerate(self) :
		"""Rate (/s) counter for appfirewallret5xxperprofile.
		"""
		try :
			return self._appfirewallret5xxperprofilerate
		except Exception as e:
			raise e

	@property
	def appfirewallviolrefererheaderperprofile(self) :
		"""Number of Referer Header security check violations seen by the Application Firewall.
		"""
		try :
			return self._appfirewallviolrefererheaderperprofile
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(appfwprofile_response, response, self.__class__.__name__.replace('_stats',''))
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.appfwprofile
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
	def  get(cls, service, name="", option_="") :
		""" Use this API to fetch the statistics of all appfwprofile_stats resources that are configured on netscaler.
		"""
		try :
			obj = appfwprofile_stats()
			if not name :
				response = obj.stat_resources(service, option_)
			else :
				obj.name = name
				response = obj.stat_resource(service, option_)
			return response
		except Exception as e:
			raise e

	class Clearstats:
		basic = "basic"
		full = "full"

class appfwprofile_response(base_response) :
	def __init__(self, length=1) :
		self.appfwprofile = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.appfwprofile = [appfwprofile_stats() for _ in range(length)]

