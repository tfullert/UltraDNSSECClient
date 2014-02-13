This is a class for making DNSSEC related calls to the UltraDNS API.  Calls
that you can make are:

* queryPendingChanges - Find out if there are any changes to a zone.
* getDnssecKeyRecordList - Get list of ZSK or KSK keys.
* getDomainDnssecPolicies - Get details of DNSSEC policies for the zone.
* getDsRecords - Get DNSSEC records for a zone.
* signZone - Sign a zone.
* unSignZone - Unsign a zone (feature must be enabled).
