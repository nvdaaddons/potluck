# Add-on update# Part of NVDA Community Add-ons Toolkit
# Copyright 2017 NVDA add-ons contributors, released under GPL

import urllib
import ctypes
import ssl
import re

# Borrowed ideas from NVDA Core.
def checkForAddonUpdate(updateURL, filenamePattern, patternKeyword):
	if updateURL is None:
		updateURL = "https://addons.nvda-project.org"
	try:
		res = urllib.urlopen(updateURL)
		res.close()
	except IOError as e:
		# SSL issue (seen in NVDA Core earlier than 2014.1).
		if isinstance(e.strerror, ssl.SSLError) and e.strerror.reason == "CERTIFICATE_VERIFY_FAILED":
			_updateWindowsRootCertificates(updateURL)
			res = urllib.urlopen(updateURL)
		else:
			raise
	if res.code != 200:
		raise RuntimeError("Checking for update failed with code %d" % res.code)
	# Build emulated add-on update dictionary if there is indeed a new version.
	version = re.search(filenamePattern, res.url).groupdict()[patternKeyword]
	if addonVersion != version:
		return {"curVersion": addonVersion, "newVersion": version, "path": res.url}
	return None

# Borrowed from NVDA Core (the only difference is the URL and where structures are coming from).
def _updateWindowsRootCertificates(url):
	crypt = ctypes.windll.crypt32
	# Get the server certificate.
	sslCont = ssl._create_unverified_context()
	u = urllib.urlopen(url, context=sslCont)
	cert = u.fp._sock.getpeercert(True)
	u.close()
	# Convert to a form usable by Windows.
	certCont = crypt.CertCreateCertificateContext(
		0x00000001, # X509_ASN_ENCODING
		cert,
		len(cert))
	# Ask Windows to build a certificate chain, thus triggering a root certificate update.
	chainCont = ctypes.c_void_p()
	crypt.CertGetCertificateChain(None, certCont, None, None,
		ctypes.byref(updateCheck.CERT_CHAIN_PARA(cbSize=ctypes.sizeof(updateCheck.CERT_CHAIN_PARA),
			RequestedUsage=updateCheck.CERT_USAGE_MATCH())),
		0, None,
		ctypes.byref(chainCont))
	crypt.CertFreeCertificateChain(chainCont)
	crypt.CertFreeCertificateContext(certCont)
