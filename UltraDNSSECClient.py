# =============================================================================
# UltraDNSSECClient.py
#
# A script for managing your DNSSEC implementation via API
# for the UltraDNS platform.
#
# Requires non-standard 'suds' python library to be installed.
#
# Version: 1.0
# Date: 02/04/14
# Author: Tyler Fullerton
# =============================================================================
import sys
from suds import WebFault
from functools import wraps
from suds.client import Client
from suds.wsse import Security, UsernameToken

# -----------------------------------------------------------------------------
# A decorator function to be used with any method calls that the client 
# makes to interact with the UltraDNS API.
def dispatch(f):
	@wraps(f)
	def wrapper(*args):
		args = list(args)
		args[1] = args[0].ensureDomainEndsWithDot(args[1])
		
		try:
			return f(*args)
		except WebFault as e:
			print '<' + e.fault.detail.UltraWSException.errorCode + '>: ' + \
				e.fault.detail.UltraWSException.errorDescription

	return wrapper

# =============================================================================
# Client class for interacting with Ultra's SOAP API.
class ultraDNSSECClient:

	ultraAPIBase = 'https://ultra-api.ultradns.com:8008/UltraDNS_WS/v01?wsdl' 

	# -------------------------------------------------------------------------
	# Create a new Client object.
	#
	# username - The username of the Ultra account.
	# password - The password of the Ultra account.
	def __init__(self, username, password):
		client		= Client(self.ultraAPIBase)
		security	= Security()
		token		= UsernameToken(username, password)
	
		security.tokens.append(token)
		client.set_options(wsse=security)
		
		self.sudsClient = client

		self.debug = False

	# -------------------------------------------------------------------------
	# Override string representation of Client object.
	def __str__(self):	
		return '' + self.sudsClient.__str__()

	# -------------------------------------------------------------------------
	# Turn on debugging for the client.
	def debugOn(self):
		self.debug = True

	# -------------------------------------------------------------------------
	# Turn off debugging for the client.
	def debugOff(self):
		self.debug = False

	# -------------------------------------------------------------------------
	# Get the service object of the suds client.
	def sudsClient(self):
		return self.sudsClient	

	# -------------------------------------------------------------------------
	# Get the service object of the suds client.
	def sudsService(self):
		return self.sudsClient.service

	# -------------------------------------------------------------------------
	# Get the factory object of the suds client.
	def sudsFactory(self):
		return self.sudsClient.factory

	# -------------------------------------------------------------------------
	# Ensure domain ends with a dot.
	def ensureDomainEndsWithDot(self, domain):
		if (not domain.endswith('.')): domain = domain + '.'
		if(self.debug): print domain

		return domain
	
	# -------------------------------------------------------------------------
	# Call UltraDNS API to query pending changes to the zone.
	@dispatch	
	def queryPendingChanges(self, domain):
		return self.sudsService().queryPendingChanges(domain)		

	# -------------------------------------------------------------------------
	# Call UltraDNS API to get DNSSEC Key Records.
	#
	# keyType - Can be either ZSK (zone signing keys) or KSK (key signing keys).
	@dispatch
	def getDnssecKeyRecordList(self, zoneName, keyType):
		return self.sudsService().getDnssecKeyRecordList(zoneName, keyType)

	# -------------------------------------------------------------------------
	# Call UltraDNS API to get DNSSEC policies for the zone.
	@dispatch	
	def getDomainDnssecPolicies(self, zoneName):
		return self.sudsService().getDomainDnssecPolicies(zoneName)

	# -------------------------------------------------------------------------
	# Call UltraDNS API to get DS records for the zone.
	@dispatch
	def getDsRecords(self, zoneName):
		return self.sudsService().getDsRecords(zoneName)
	
	# -------------------------------------------------------------------------
	# Call UltraDNS API to sign the zone.
	@dispatch
	def signZone(self, zoneName):
		return self.sudsService().signZone(zoneName)

	# -------------------------------------------------------------------------
	# Call UltraDNS API to unsign the zone.
	@dispatch
	def unSignZone(self, zoneName):
		return self.sudsService().unsignZone(zoneName)

# -----------------------------------------------------------------------------
# Main driver for running the text code below.
def driver():
	username	= '[USERNAME]'
	password	= '[PASSWORD]'
	domain		= '[ZONE]'
	myClient	= ultraDNSSECClient(username, password)
	
	myClient.debugOn()

	result		= myClient.queryPendingChanges(domain)
	result		= myClient.getDnssecKeyRecordList(domain, 'ZSK')
	result		= myClient.getDomainDnssecPolicies(domain)
	result		= myClient.getDsRecords(domain)
	result		= myClient.signZone(domain)
	result		= myClient.unSignZone(domain)

# -----------------------------------------------------------------------------
# Testing code
if __name__ == '__main__':

	sys.exit(driver())
