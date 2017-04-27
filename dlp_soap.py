# --
# File: dlp_soap.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# http://lxml.de/tutorial.html
from lxml.builder import ElementMaker
from lxml import etree

# The name spaces
SOAP_ENVELOPE_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
INCIDENT_NAMESPACE = "http://www.vontu.com/v2011/enforce/webservice/incident/schema"

# namespace map
NSMAP2 = {None: ''}

# Elements used
NS2 = ElementMaker(namespace=None, nsmap=None)


def xml_get_incident_list(report_id, creation_later_than_date):

    NS1 = ElementMaker(namespace=INCIDENT_NAMESPACE, nsmap={"soap-env": SOAP_ENVELOPE_NAMESPACE, "ns1": INCIDENT_NAMESPACE})

    return NS1.incidentListRequest(NS2.savedReportId(report_id), NS2.incidentCreationDateLaterThan(creation_later_than_date))


def xml_get_incident_details(incident_id):

    NS1 = ElementMaker(namespace=INCIDENT_NAMESPACE, nsmap={"soap-env": SOAP_ENVELOPE_NAMESPACE, "ns1": INCIDENT_NAMESPACE})

    return NS1.incidentDetailRequest(NS2.incidentLongId(incident_id), NS2.includeImageViolations('true'))


def xml_get_incident_binaries(incident_id):

    NS1 = ElementMaker(namespace=INCIDENT_NAMESPACE, nsmap={"soap-env": SOAP_ENVELOPE_NAMESPACE, "ns1": INCIDENT_NAMESPACE})

    return NS1.incidentBinariesRequest(NS2.incidentLongId(incident_id), NS2.includeOriginalMessage('true'), NS2.includeAllComponents('true'))


def add_to_envelope(lxml_obj, target_user=None):

    S = ElementMaker(namespace=SOAP_ENVELOPE_NAMESPACE, nsmap={"soap-env": SOAP_ENVELOPE_NAMESPACE})

    return S.Envelope(S.Body(lxml_obj))


def get_string(lxml_obj):
    return etree.tostring(lxml_obj, encoding='utf-8')
