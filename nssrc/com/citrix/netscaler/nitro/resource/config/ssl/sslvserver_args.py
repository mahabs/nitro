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


class sslvserver_args :
	""" Provides additional arguments required for fetching the sslvserver resource.
	"""
	def __init__(self) :
		self._cipherdetails = False

	@property
	def cipherdetails(self) :
		"""Display details of the individual ciphers bound to the SSL virtual server.
		"""
		try :
			return self._cipherdetails
		except Exception as e:
			raise e

	@cipherdetails.setter
	def cipherdetails(self, cipherdetails) :
		"""Display details of the individual ciphers bound to the SSL virtual server.
		"""
		try :
			self._cipherdetails = cipherdetails
		except Exception as e:
			raise e

