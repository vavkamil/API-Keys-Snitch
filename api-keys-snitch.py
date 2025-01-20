#!/usr/bin/env python3

import re
from array import array
from java.io import PrintWriter

from burp import IScanIssue
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IExtensionStateListener


regexes = {
    "Google API": "AIza[0-9A-Za-z-_]{35}",
    "Google Captcha": "6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "Google OAuth": "ya29\.[0-9A-Za-z\-_]+",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
}


class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("API Keys Snitch with Semgrep Patterns")
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # Register scanner checks & extension state listener
        callbacks.registerScannerCheck(self)
        callbacks.registerExtensionStateListener(self)

        # Print out some credits
        self._stdout.println("GitHub: https://github.com/vavkamil/api-keys-snitch")
        self._stdout.println("Twitter: https://twitter.com/vavkamil")
        self._stdout.println("Blog: https://vavkamil.cz")
        self._stdout.println("")

    #
    # implement IExtensionStateListener
    #
    def extensionUnloaded(self):
        self._stdout.println("Extension was unloaded")

    #
    # Helper method to locate a literal match within response bytes
    #
    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)

        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array("i", [start, start + matchlen]))
            start += matchlen
        return matches

    #
    # implement IScannerCheck
    #
    def doPassiveScan(self, baseRequestResponse):
        # Only scan if the response is likely JS (by extension and/or content-type)
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        url = request_info.getUrl()
        path = url.getPath() if url else ""

        # Simple approach: if not .js, ignore
        if not path.endswith(".js"):
            return None

        # Also check the Content-Type
        response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        headers = response_info.getHeaders()
        content_type_js = any(
            "Content-Type: application/javascript" in h
            or "Content-Type: text/javascript" in h
            for h in headers
        )
        # If it doesn't look like JS, skip as well
        if not content_type_js and not path.endswith(".js"):
            return None

        response_bytes = baseRequestResponse.getResponse()
        if not response_bytes:
            return None

        response_str = self._helpers.bytesToString(response_bytes)

        scan_issues = []
        # Check each regex
        for regex_name, pattern_str in regexes.items():
            pattern = re.compile(pattern_str)
            found_strings = pattern.findall(response_str)
            if not found_strings:
                continue

            # If the regex uses a capturing group, sometimes findall() returns tuples
            # For a single capture group, found_strings might look like ['match1','match2'] or
            # a list of tuples. We can normalize:
            if isinstance(found_strings[0], tuple):
                # Flatten each tuple to pick the first capturing group
                found_strings = [m[0] for m in found_strings]

            # Create one issue per match
            for found_string in found_strings:
                offsets = self._get_matches(response_bytes, found_string)
                if not offsets:
                    continue

                detail_msg = (
                    "The response contains a <strong>{}</strong>: <strong>{}</strong><br><br>"
                    "Regex pattern used: <strong>{}</strong>"
                ).format(regex_name, found_string, pattern_str)

                scan_issues.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        request_info.getUrl(),
                        [
                            self._callbacks.applyMarkers(
                                baseRequestResponse, None, offsets
                            )
                        ],
                        detail_msg,
                    )
                )

        return scan_issues if scan_issues else None

    def doActiveScan(self, baseRequestResponse):
        """For many secrets checks, passive is sufficient.
        But here we mirror the same approach if you still want it in activeScan."""
        return self.doPassiveScan(baseRequestResponse)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1  # -1 => Only report the existing issue
        return 0  #  0 => Report both issues


#
# Class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, detail):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "API Keys Snitch"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return """
            Sometimes API Keys used within websites are not properly restricted or over-privileged.<br>
            Make sure to test them manually to verify correct usage and scoping.<br><br>
            For example, <a href='https://github.com/streaak/keyhacks' target='_blank'>KeyHacks</a> shows ways
            in which particular API keys can be checked for validity or privileges.
        """

    def getRemediationBackground(self):
        return """
            - Rotate your keys regularly.
            - Restrict them to necessary permissions only.
            - Avoid committing them in client-side JavaScript whenever possible.
        """

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
