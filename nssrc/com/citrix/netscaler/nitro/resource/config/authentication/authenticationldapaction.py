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

class authenticationldapaction(base_resource) :
	""" Configuration for LDAP action resource. """
	def __init__(self) :
		self._name = ""
		self._serverip = ""
		self._servername = ""
		self._serverport = 0
		self._authtimeout = 0
		self._ldapbase = ""
		self._ldapbinddn = ""
		self._ldapbinddnpassword = ""
		self._ldaploginname = ""
		self._searchfilter = ""
		self._groupattrname = ""
		self._subattributename = ""
		self._sectype = ""
		self._svrtype = ""
		self._ssonameattribute = ""
		self._authentication = ""
		self._requireuser = ""
		self._passwdchange = ""
		self._nestedgroupextraction = ""
		self._maxnestinglevel = 0
		self._followreferrals = ""
		self._maxldapreferrals = 0
		self._validateservercert = ""
		self._ldaphostname = ""
		self._groupnameidentifier = ""
		self._groupsearchattribute = ""
		self._groupsearchsubattribute = ""
		self._groupsearchfilter = ""
		self._defaultauthenticationgroup = ""
		self._success = 0
		self._failure = 0
		self.___count = 0

	@property
	def name(self) :
		"""Name for the new LDAP action. 
		Must begin with a letter, number, or the underscore character (_), and must contain only letters, numbers, and the hyphen (-), period (.) pound (#), space ( ), at (@), equals (=), colon (:), and underscore characters. Cannot be changed after the LDAP action is added.
		The following requirement applies only to the NetScaler CLI:
		If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my authentication action" or 'my authentication action').<br/>Minimum length =  1.
		"""
		try :
			return self._name
		except Exception as e:
			raise e

	@name.setter
	def name(self, name) :
		"""Name for the new LDAP action. 
		Must begin with a letter, number, or the underscore character (_), and must contain only letters, numbers, and the hyphen (-), period (.) pound (#), space ( ), at (@), equals (=), colon (:), and underscore characters. Cannot be changed after the LDAP action is added.
		The following requirement applies only to the NetScaler CLI:
		If the name includes one or more spaces, enclose the name in double or single quotation marks (for example, "my authentication action" or 'my authentication action').<br/>Minimum length =  1
		"""
		try :
			self._name = name
		except Exception as e:
			raise e

	@property
	def serverip(self) :
		"""IP address assigned to the LDAP server.<br/>Minimum length =  1.
		"""
		try :
			return self._serverip
		except Exception as e:
			raise e

	@serverip.setter
	def serverip(self, serverip) :
		"""IP address assigned to the LDAP server.<br/>Minimum length =  1
		"""
		try :
			self._serverip = serverip
		except Exception as e:
			raise e

	@property
	def servername(self) :
		"""LDAP server name as a FQDN.  Mutually exclusive with LDAP IP address.<br/>Minimum length =  1.
		"""
		try :
			return self._servername
		except Exception as e:
			raise e

	@servername.setter
	def servername(self, servername) :
		"""LDAP server name as a FQDN.  Mutually exclusive with LDAP IP address.<br/>Minimum length =  1
		"""
		try :
			self._servername = servername
		except Exception as e:
			raise e

	@property
	def serverport(self) :
		"""Port on which the LDAP server accepts connections.<br/>Default value: 389<br/>Minimum length =  1.
		"""
		try :
			return self._serverport
		except Exception as e:
			raise e

	@serverport.setter
	def serverport(self, serverport) :
		"""Port on which the LDAP server accepts connections.<br/>Default value: 389<br/>Minimum length =  1
		"""
		try :
			self._serverport = serverport
		except Exception as e:
			raise e

	@property
	def authtimeout(self) :
		"""Number of seconds the NetScaler appliance waits for a response from the RADIUS server.<br/>Default value: 3<br/>Minimum length =  1.
		"""
		try :
			return self._authtimeout
		except Exception as e:
			raise e

	@authtimeout.setter
	def authtimeout(self, authtimeout) :
		"""Number of seconds the NetScaler appliance waits for a response from the RADIUS server.<br/>Default value: 3<br/>Minimum length =  1
		"""
		try :
			self._authtimeout = authtimeout
		except Exception as e:
			raise e

	@property
	def ldapbase(self) :
		"""Base (node) from which to start LDAP searches. 
		If the LDAP server is running locally, the default value of base is dc=netscaler, dc=com.
		"""
		try :
			return self._ldapbase
		except Exception as e:
			raise e

	@ldapbase.setter
	def ldapbase(self, ldapbase) :
		"""Base (node) from which to start LDAP searches. 
		If the LDAP server is running locally, the default value of base is dc=netscaler, dc=com.
		"""
		try :
			self._ldapbase = ldapbase
		except Exception as e:
			raise e

	@property
	def ldapbinddn(self) :
		"""Full distinguished name (DN) that is used to bind to the LDAP server. 
		Default: cn=Manager,dc=netscaler,dc=com.
		"""
		try :
			return self._ldapbinddn
		except Exception as e:
			raise e

	@ldapbinddn.setter
	def ldapbinddn(self, ldapbinddn) :
		"""Full distinguished name (DN) that is used to bind to the LDAP server. 
		Default: cn=Manager,dc=netscaler,dc=com.
		"""
		try :
			self._ldapbinddn = ldapbinddn
		except Exception as e:
			raise e

	@property
	def ldapbinddnpassword(self) :
		"""Password used to bind to the LDAP server.<br/>Minimum length =  1.
		"""
		try :
			return self._ldapbinddnpassword
		except Exception as e:
			raise e

	@ldapbinddnpassword.setter
	def ldapbinddnpassword(self, ldapbinddnpassword) :
		"""Password used to bind to the LDAP server.<br/>Minimum length =  1
		"""
		try :
			self._ldapbinddnpassword = ldapbinddnpassword
		except Exception as e:
			raise e

	@property
	def ldaploginname(self) :
		"""LDAP login name attribute. 
		The NetScaler appliance uses the LDAP login name to query external LDAP servers or Active Directories.
		"""
		try :
			return self._ldaploginname
		except Exception as e:
			raise e

	@ldaploginname.setter
	def ldaploginname(self, ldaploginname) :
		"""LDAP login name attribute. 
		The NetScaler appliance uses the LDAP login name to query external LDAP servers or Active Directories.
		"""
		try :
			self._ldaploginname = ldaploginname
		except Exception as e:
			raise e

	@property
	def searchfilter(self) :
		"""String to be combined with the default LDAP user search string to form the search value. For example, if the search filter ""vpnallowed=true"" is combined with the LDAP login name ""samaccount"" and the user-supplied username is ""bob"", the result is the LDAP search string ""(&(vpnallowed=true)(samaccount=bob)"" (Be sure to enclose the search string in two sets of double quotation marks; both sets are needed.).<br/>Minimum length =  1.
		"""
		try :
			return self._searchfilter
		except Exception as e:
			raise e

	@searchfilter.setter
	def searchfilter(self, searchfilter) :
		"""String to be combined with the default LDAP user search string to form the search value. For example, if the search filter ""vpnallowed=true"" is combined with the LDAP login name ""samaccount"" and the user-supplied username is ""bob"", the result is the LDAP search string ""(&(vpnallowed=true)(samaccount=bob)"" (Be sure to enclose the search string in two sets of double quotation marks; both sets are needed.).<br/>Minimum length =  1
		"""
		try :
			self._searchfilter = searchfilter
		except Exception as e:
			raise e

	@property
	def groupattrname(self) :
		"""LDAP group attribute name.
		Used for group extraction on the LDAP server.
		"""
		try :
			return self._groupattrname
		except Exception as e:
			raise e

	@groupattrname.setter
	def groupattrname(self, groupattrname) :
		"""LDAP group attribute name.
		Used for group extraction on the LDAP server.
		"""
		try :
			self._groupattrname = groupattrname
		except Exception as e:
			raise e

	@property
	def subattributename(self) :
		"""LDAP group sub-attribute name. 
		Used for group extraction from the LDAP server.
		"""
		try :
			return self._subattributename
		except Exception as e:
			raise e

	@subattributename.setter
	def subattributename(self, subattributename) :
		"""LDAP group sub-attribute name. 
		Used for group extraction from the LDAP server.
		"""
		try :
			self._subattributename = subattributename
		except Exception as e:
			raise e

	@property
	def sectype(self) :
		"""Type of security used for communications between the NetScaler appliance and the LDAP server. For the PLAINTEXT setting, no encryption is required.<br/>Default value: PLAINTEXT<br/>Possible values = PLAINTEXT, TLS, SSL.
		"""
		try :
			return self._sectype
		except Exception as e:
			raise e

	@sectype.setter
	def sectype(self, sectype) :
		"""Type of security used for communications between the NetScaler appliance and the LDAP server. For the PLAINTEXT setting, no encryption is required.<br/>Default value: PLAINTEXT<br/>Possible values = PLAINTEXT, TLS, SSL
		"""
		try :
			self._sectype = sectype
		except Exception as e:
			raise e

	@property
	def svrtype(self) :
		"""The type of LDAP server.<br/>Default value: AAA_LDAP_SERVER_TYPE_DEFAULT<br/>Possible values = AD, NDS.
		"""
		try :
			return self._svrtype
		except Exception as e:
			raise e

	@svrtype.setter
	def svrtype(self, svrtype) :
		"""The type of LDAP server.<br/>Default value: AAA_LDAP_SERVER_TYPE_DEFAULT<br/>Possible values = AD, NDS
		"""
		try :
			self._svrtype = svrtype
		except Exception as e:
			raise e

	@property
	def ssonameattribute(self) :
		"""LDAP single signon (SSO) attribute. 
		The NetScaler appliance uses the SSO name attribute to query external LDAP servers or Active Directories for an alternate username.
		"""
		try :
			return self._ssonameattribute
		except Exception as e:
			raise e

	@ssonameattribute.setter
	def ssonameattribute(self, ssonameattribute) :
		"""LDAP single signon (SSO) attribute. 
		The NetScaler appliance uses the SSO name attribute to query external LDAP servers or Active Directories for an alternate username.
		"""
		try :
			self._ssonameattribute = ssonameattribute
		except Exception as e:
			raise e

	@property
	def authentication(self) :
		"""Perform LDAP authentication.
		If authentication is disabled, any LDAP authentication attempt returns authentication success if the user is found. 
		CAUTION! Authentication should be disabled only for authorization group extraction or where other (non-LDAP) authentication methods are in use and either bound to a primary list or flagged as secondary.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._authentication
		except Exception as e:
			raise e

	@authentication.setter
	def authentication(self, authentication) :
		"""Perform LDAP authentication.
		If authentication is disabled, any LDAP authentication attempt returns authentication success if the user is found. 
		CAUTION! Authentication should be disabled only for authorization group extraction or where other (non-LDAP) authentication methods are in use and either bound to a primary list or flagged as secondary.<br/>Default value: ENABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._authentication = authentication
		except Exception as e:
			raise e

	@property
	def requireuser(self) :
		"""Require a successful user search for authentication.<br/>Default value: YES<br/>Possible values = YES, NO.
		"""
		try :
			return self._requireuser
		except Exception as e:
			raise e

	@requireuser.setter
	def requireuser(self, requireuser) :
		"""Require a successful user search for authentication.<br/>Default value: YES<br/>Possible values = YES, NO
		"""
		try :
			self._requireuser = requireuser
		except Exception as e:
			raise e

	@property
	def passwdchange(self) :
		"""Allow password change requests.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED.
		"""
		try :
			return self._passwdchange
		except Exception as e:
			raise e

	@passwdchange.setter
	def passwdchange(self, passwdchange) :
		"""Allow password change requests.<br/>Default value: DISABLED<br/>Possible values = ENABLED, DISABLED
		"""
		try :
			self._passwdchange = passwdchange
		except Exception as e:
			raise e

	@property
	def nestedgroupextraction(self) :
		"""Allow nested group extraction, in which the NetScaler appliance queries external LDAP servers to determine whether a group is part of another group.<br/>Default value: OFF<br/>Possible values = ON, OFF.
		"""
		try :
			return self._nestedgroupextraction
		except Exception as e:
			raise e

	@nestedgroupextraction.setter
	def nestedgroupextraction(self, nestedgroupextraction) :
		"""Allow nested group extraction, in which the NetScaler appliance queries external LDAP servers to determine whether a group is part of another group.<br/>Default value: OFF<br/>Possible values = ON, OFF
		"""
		try :
			self._nestedgroupextraction = nestedgroupextraction
		except Exception as e:
			raise e

	@property
	def maxnestinglevel(self) :
		"""If nested group extraction is ON, specifies the number of levels up to which group extraction is performed.<br/>Default value: 2<br/>Minimum length =  2.
		"""
		try :
			return self._maxnestinglevel
		except Exception as e:
			raise e

	@maxnestinglevel.setter
	def maxnestinglevel(self, maxnestinglevel) :
		"""If nested group extraction is ON, specifies the number of levels up to which group extraction is performed.<br/>Default value: 2<br/>Minimum length =  2
		"""
		try :
			self._maxnestinglevel = maxnestinglevel
		except Exception as e:
			raise e

	@property
	def followreferrals(self) :
		"""Setting this option to ON enables following LDAP referrals received from the LDAP server.<br/>Default value: OFF<br/>Possible values = ON, OFF.
		"""
		try :
			return self._followreferrals
		except Exception as e:
			raise e

	@followreferrals.setter
	def followreferrals(self, followreferrals) :
		"""Setting this option to ON enables following LDAP referrals received from the LDAP server.<br/>Default value: OFF<br/>Possible values = ON, OFF
		"""
		try :
			self._followreferrals = followreferrals
		except Exception as e:
			raise e

	@property
	def maxldapreferrals(self) :
		"""Specifies the maximum number of nested referrals to follow.<br/>Default value: 1<br/>Minimum length =  1.
		"""
		try :
			return self._maxldapreferrals
		except Exception as e:
			raise e

	@maxldapreferrals.setter
	def maxldapreferrals(self, maxldapreferrals) :
		"""Specifies the maximum number of nested referrals to follow.<br/>Default value: 1<br/>Minimum length =  1
		"""
		try :
			self._maxldapreferrals = maxldapreferrals
		except Exception as e:
			raise e

	@property
	def validateservercert(self) :
		"""When to validate LDAP server certs.<br/>Default value: NO<br/>Possible values = YES, NO.
		"""
		try :
			return self._validateservercert
		except Exception as e:
			raise e

	@validateservercert.setter
	def validateservercert(self, validateservercert) :
		"""When to validate LDAP server certs.<br/>Default value: NO<br/>Possible values = YES, NO
		"""
		try :
			self._validateservercert = validateservercert
		except Exception as e:
			raise e

	@property
	def ldaphostname(self) :
		"""Hostname for the LDAP server.  If -validateServerCert is ON then this must be the host name on the certificate from the LDAP server.
		A hostname mismatch will cause a connection failure.
		"""
		try :
			return self._ldaphostname
		except Exception as e:
			raise e

	@ldaphostname.setter
	def ldaphostname(self, ldaphostname) :
		"""Hostname for the LDAP server.  If -validateServerCert is ON then this must be the host name on the certificate from the LDAP server.
		A hostname mismatch will cause a connection failure.
		"""
		try :
			self._ldaphostname = ldaphostname
		except Exception as e:
			raise e

	@property
	def groupnameidentifier(self) :
		"""Name that uniquely identifies a group in LDAP or Active Directory.
		"""
		try :
			return self._groupnameidentifier
		except Exception as e:
			raise e

	@groupnameidentifier.setter
	def groupnameidentifier(self, groupnameidentifier) :
		"""Name that uniquely identifies a group in LDAP or Active Directory.
		"""
		try :
			self._groupnameidentifier = groupnameidentifier
		except Exception as e:
			raise e

	@property
	def groupsearchattribute(self) :
		"""LDAP group search attribute. 
		Used to determine to which groups a group belongs.
		"""
		try :
			return self._groupsearchattribute
		except Exception as e:
			raise e

	@groupsearchattribute.setter
	def groupsearchattribute(self, groupsearchattribute) :
		"""LDAP group search attribute. 
		Used to determine to which groups a group belongs.
		"""
		try :
			self._groupsearchattribute = groupsearchattribute
		except Exception as e:
			raise e

	@property
	def groupsearchsubattribute(self) :
		"""LDAP group search subattribute. 
		Used to determine to which groups a group belongs.
		"""
		try :
			return self._groupsearchsubattribute
		except Exception as e:
			raise e

	@groupsearchsubattribute.setter
	def groupsearchsubattribute(self, groupsearchsubattribute) :
		"""LDAP group search subattribute. 
		Used to determine to which groups a group belongs.
		"""
		try :
			self._groupsearchsubattribute = groupsearchsubattribute
		except Exception as e:
			raise e

	@property
	def groupsearchfilter(self) :
		"""String to be combined with the default LDAP group search string to form the search value.  For example, the group search filter ""vpnallowed=true"" when combined with the group identifier ""samaccount"" and the group name ""g1"" yields the LDAP search string ""(&(vpnallowed=true)(samaccount=g1)"". (Be sure to enclose the search string in two sets of double quotation marks; both sets are needed.).
		"""
		try :
			return self._groupsearchfilter
		except Exception as e:
			raise e

	@groupsearchfilter.setter
	def groupsearchfilter(self, groupsearchfilter) :
		"""String to be combined with the default LDAP group search string to form the search value.  For example, the group search filter ""vpnallowed=true"" when combined with the group identifier ""samaccount"" and the group name ""g1"" yields the LDAP search string ""(&(vpnallowed=true)(samaccount=g1)"". (Be sure to enclose the search string in two sets of double quotation marks; both sets are needed.).
		"""
		try :
			self._groupsearchfilter = groupsearchfilter
		except Exception as e:
			raise e

	@property
	def defaultauthenticationgroup(self) :
		"""This is the default group that is chosen when the authentication succeeds in addition to extracted groups.<br/>Maximum length =  64.
		"""
		try :
			return self._defaultauthenticationgroup
		except Exception as e:
			raise e

	@defaultauthenticationgroup.setter
	def defaultauthenticationgroup(self, defaultauthenticationgroup) :
		"""This is the default group that is chosen when the authentication succeeds in addition to extracted groups.<br/>Maximum length =  64
		"""
		try :
			self._defaultauthenticationgroup = defaultauthenticationgroup
		except Exception as e:
			raise e

	@property
	def success(self) :
		try :
			return self._success
		except Exception as e:
			raise e

	@property
	def failure(self) :
		try :
			return self._failure
		except Exception as e:
			raise e

	def _get_nitro_response(self, service, response) :
		""" converts nitro response into object and returns the object array in case of get request.
		"""
		try :
			result = service.payload_formatter.string_to_resource(authenticationldapaction_response, response, self.__class__.__name__)
			if(result.errorcode != 0) :
				if (result.errorcode == 444) :
					service.clear_session(self)
				if result.severity :
					if (result.severity == "ERROR") :
						raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
				else :
					raise nitro_exception(result.errorcode, str(result.message), str(result.severity))
			return result.authenticationldapaction
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
		""" Use this API to add authenticationldapaction.
		"""
		try :
			if type(resource) is not list :
				addresource = authenticationldapaction()
				addresource.name = resource.name
				addresource.serverip = resource.serverip
				addresource.servername = resource.servername
				addresource.serverport = resource.serverport
				addresource.authtimeout = resource.authtimeout
				addresource.ldapbase = resource.ldapbase
				addresource.ldapbinddn = resource.ldapbinddn
				addresource.ldapbinddnpassword = resource.ldapbinddnpassword
				addresource.ldaploginname = resource.ldaploginname
				addresource.searchfilter = resource.searchfilter
				addresource.groupattrname = resource.groupattrname
				addresource.subattributename = resource.subattributename
				addresource.sectype = resource.sectype
				addresource.svrtype = resource.svrtype
				addresource.ssonameattribute = resource.ssonameattribute
				addresource.authentication = resource.authentication
				addresource.requireuser = resource.requireuser
				addresource.passwdchange = resource.passwdchange
				addresource.nestedgroupextraction = resource.nestedgroupextraction
				addresource.maxnestinglevel = resource.maxnestinglevel
				addresource.followreferrals = resource.followreferrals
				addresource.maxldapreferrals = resource.maxldapreferrals
				addresource.validateservercert = resource.validateservercert
				addresource.ldaphostname = resource.ldaphostname
				addresource.groupnameidentifier = resource.groupnameidentifier
				addresource.groupsearchattribute = resource.groupsearchattribute
				addresource.groupsearchsubattribute = resource.groupsearchsubattribute
				addresource.groupsearchfilter = resource.groupsearchfilter
				addresource.defaultauthenticationgroup = resource.defaultauthenticationgroup
				return addresource.add_resource(client)
			else :
				if (resource and len(resource) > 0) :
					addresources = [ authenticationldapaction() for _ in range(len(resource))]
					for i in range(len(resource)) :
						addresources[i].name = resource[i].name
						addresources[i].serverip = resource[i].serverip
						addresources[i].servername = resource[i].servername
						addresources[i].serverport = resource[i].serverport
						addresources[i].authtimeout = resource[i].authtimeout
						addresources[i].ldapbase = resource[i].ldapbase
						addresources[i].ldapbinddn = resource[i].ldapbinddn
						addresources[i].ldapbinddnpassword = resource[i].ldapbinddnpassword
						addresources[i].ldaploginname = resource[i].ldaploginname
						addresources[i].searchfilter = resource[i].searchfilter
						addresources[i].groupattrname = resource[i].groupattrname
						addresources[i].subattributename = resource[i].subattributename
						addresources[i].sectype = resource[i].sectype
						addresources[i].svrtype = resource[i].svrtype
						addresources[i].ssonameattribute = resource[i].ssonameattribute
						addresources[i].authentication = resource[i].authentication
						addresources[i].requireuser = resource[i].requireuser
						addresources[i].passwdchange = resource[i].passwdchange
						addresources[i].nestedgroupextraction = resource[i].nestedgroupextraction
						addresources[i].maxnestinglevel = resource[i].maxnestinglevel
						addresources[i].followreferrals = resource[i].followreferrals
						addresources[i].maxldapreferrals = resource[i].maxldapreferrals
						addresources[i].validateservercert = resource[i].validateservercert
						addresources[i].ldaphostname = resource[i].ldaphostname
						addresources[i].groupnameidentifier = resource[i].groupnameidentifier
						addresources[i].groupsearchattribute = resource[i].groupsearchattribute
						addresources[i].groupsearchsubattribute = resource[i].groupsearchsubattribute
						addresources[i].groupsearchfilter = resource[i].groupsearchfilter
						addresources[i].defaultauthenticationgroup = resource[i].defaultauthenticationgroup
				result = cls.add_bulk_request(client, addresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def delete(cls, client, resource) :
		""" Use this API to delete authenticationldapaction.
		"""
		try :
			if type(resource) is not list :
				deleteresource = authenticationldapaction()
				if type(resource) !=  type(deleteresource):
					deleteresource.name = resource
				else :
					deleteresource.name = resource.name
				return deleteresource.delete_resource(client)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						deleteresources = [ authenticationldapaction() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						deleteresources = [ authenticationldapaction() for _ in range(len(resource))]
						for i in range(len(resource)) :
							deleteresources[i].name = resource[i].name
				result = cls.delete_bulk_request(client, deleteresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def update(cls, client, resource) :
		""" Use this API to update authenticationldapaction.
		"""
		try :
			if type(resource) is not list :
				updateresource = authenticationldapaction()
				updateresource.name = resource.name
				updateresource.serverip = resource.serverip
				updateresource.servername = resource.servername
				updateresource.serverport = resource.serverport
				updateresource.authtimeout = resource.authtimeout
				updateresource.ldapbase = resource.ldapbase
				updateresource.ldapbinddn = resource.ldapbinddn
				updateresource.ldapbinddnpassword = resource.ldapbinddnpassword
				updateresource.ldaploginname = resource.ldaploginname
				updateresource.searchfilter = resource.searchfilter
				updateresource.groupattrname = resource.groupattrname
				updateresource.subattributename = resource.subattributename
				updateresource.sectype = resource.sectype
				updateresource.svrtype = resource.svrtype
				updateresource.ssonameattribute = resource.ssonameattribute
				updateresource.authentication = resource.authentication
				updateresource.requireuser = resource.requireuser
				updateresource.passwdchange = resource.passwdchange
				updateresource.validateservercert = resource.validateservercert
				updateresource.ldaphostname = resource.ldaphostname
				updateresource.nestedgroupextraction = resource.nestedgroupextraction
				updateresource.maxnestinglevel = resource.maxnestinglevel
				updateresource.groupnameidentifier = resource.groupnameidentifier
				updateresource.groupsearchattribute = resource.groupsearchattribute
				updateresource.groupsearchsubattribute = resource.groupsearchsubattribute
				updateresource.groupsearchfilter = resource.groupsearchfilter
				updateresource.followreferrals = resource.followreferrals
				updateresource.maxldapreferrals = resource.maxldapreferrals
				updateresource.defaultauthenticationgroup = resource.defaultauthenticationgroup
				return updateresource.update_resource(client)
			else :
				if (resource and len(resource) > 0) :
					updateresources = [ authenticationldapaction() for _ in range(len(resource))]
					for i in range(len(resource)) :
						updateresources[i].name = resource[i].name
						updateresources[i].serverip = resource[i].serverip
						updateresources[i].servername = resource[i].servername
						updateresources[i].serverport = resource[i].serverport
						updateresources[i].authtimeout = resource[i].authtimeout
						updateresources[i].ldapbase = resource[i].ldapbase
						updateresources[i].ldapbinddn = resource[i].ldapbinddn
						updateresources[i].ldapbinddnpassword = resource[i].ldapbinddnpassword
						updateresources[i].ldaploginname = resource[i].ldaploginname
						updateresources[i].searchfilter = resource[i].searchfilter
						updateresources[i].groupattrname = resource[i].groupattrname
						updateresources[i].subattributename = resource[i].subattributename
						updateresources[i].sectype = resource[i].sectype
						updateresources[i].svrtype = resource[i].svrtype
						updateresources[i].ssonameattribute = resource[i].ssonameattribute
						updateresources[i].authentication = resource[i].authentication
						updateresources[i].requireuser = resource[i].requireuser
						updateresources[i].passwdchange = resource[i].passwdchange
						updateresources[i].validateservercert = resource[i].validateservercert
						updateresources[i].ldaphostname = resource[i].ldaphostname
						updateresources[i].nestedgroupextraction = resource[i].nestedgroupextraction
						updateresources[i].maxnestinglevel = resource[i].maxnestinglevel
						updateresources[i].groupnameidentifier = resource[i].groupnameidentifier
						updateresources[i].groupsearchattribute = resource[i].groupsearchattribute
						updateresources[i].groupsearchsubattribute = resource[i].groupsearchsubattribute
						updateresources[i].groupsearchfilter = resource[i].groupsearchfilter
						updateresources[i].followreferrals = resource[i].followreferrals
						updateresources[i].maxldapreferrals = resource[i].maxldapreferrals
						updateresources[i].defaultauthenticationgroup = resource[i].defaultauthenticationgroup
				result = cls.update_bulk_request(client, updateresources)
			return result
		except Exception as e :
			raise e

	@classmethod
	def unset(cls, client, resource, args) :
		""" Use this API to unset the properties of authenticationldapaction resource.
		Properties that need to be unset are specified in args array.
		"""
		try :
			if type(resource) is not list :
				unsetresource = authenticationldapaction()
				if type(resource) !=  type(unsetresource):
					unsetresource.name = resource
				else :
					unsetresource.name = resource.name
				return unsetresource.unset_resource(client, args)
			else :
				if type(resource[0]) != cls :
					if (resource and len(resource) > 0) :
						unsetresources = [ authenticationldapaction() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i]
				else :
					if (resource and len(resource) > 0) :
						unsetresources = [ authenticationldapaction() for _ in range(len(resource))]
						for i in range(len(resource)) :
							unsetresources[i].name = resource[i].name
				result = cls.unset_bulk_request(client, unsetresources, args)
			return result
		except Exception as e :
			raise e

	@classmethod
	def get(cls, client, name="", option_="") :
		""" Use this API to fetch all the authenticationldapaction resources that are configured on netscaler.
		"""
		try :
			if not name :
				obj = authenticationldapaction()
				response = obj.get_resources(client, option_)
			else :
				if type(name) != cls :
					if type(name) is not list :
						obj = authenticationldapaction()
						obj.name = name
						response = obj.get_resource(client, option_)
					else :
						if name and len(name) > 0 :
							response = [authenticationldapaction() for _ in range(len(name))]
							obj = [authenticationldapaction() for _ in range(len(name))]
							for i in range(len(name)) :
								obj[i] = authenticationldapaction()
								obj[i].name = name[i]
								response[i] = obj[i].get_resource(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def get_filtered(cls, client, filter_) :
		""" Use this API to fetch filtered set of authenticationldapaction resources.
		filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = authenticationldapaction()
			option_ = options()
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			return response
		except Exception as e :
			raise e


	@classmethod
	def count(cls, client) :
		""" Use this API to count the authenticationldapaction resources configured on NetScaler.
		"""
		try :
			obj = authenticationldapaction()
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
		""" Use this API to count filtered the set of authenticationldapaction resources.
		Filter string should be in JSON format.eg: "port:80,servicetype:HTTP".
		"""
		try :
			obj = authenticationldapaction()
			option_ = options()
			option_.count = True
			option_.filter = filter_
			response = obj.getfiltered(client, option_)
			if response :
				return response[0].__dict__['___count']
			return 0
		except Exception as e :
			raise e


	class Passwdchange:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Sectype:
		PLAINTEXT = "PLAINTEXT"
		TLS = "TLS"
		SSL = "SSL"

	class Authentication:
		ENABLED = "ENABLED"
		DISABLED = "DISABLED"

	class Requireuser:
		YES = "YES"
		NO = "NO"

	class Validateservercert:
		YES = "YES"
		NO = "NO"

	class Followreferrals:
		ON = "ON"
		OFF = "OFF"

	class Svrtype:
		AD = "AD"
		NDS = "NDS"

	class Nestedgroupextraction:
		ON = "ON"
		OFF = "OFF"

class authenticationldapaction_response(base_response) :
	def __init__(self, length=1) :
		self.authenticationldapaction = []
		self.errorcode = 0
		self.message = ""
		self.severity = ""
		self.sessionid = ""
		self.authenticationldapaction = [authenticationldapaction() for _ in range(length)]

