#!/usr/bin/env python3

#
#
#

#
#
#
#

from burp import IExtensionStateListener
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array
import re

#
#
#
#
#
#
#
#

#


regexes = {
    "Google API": "AIza[0-9A-Za-z-_]{35}",
    "Google Captcha": "6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "Google OAuth": "ya29\.[0-9A-Za-z\-_]+",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    # "": "",
    # "": "",
    # "": "",
    # "": "",
    # "": "",
}


class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("API Keys Snitch")

        # obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)

        # Print out some credits
        self._stdout.println("GitHub: https://github.com/vavkamil/api-keys-snitch")
        self._stdout.println("Twitter: https://twitter.com/vavkamil")
        self._stdout.println("Blog: https://vavkamil.cz")
        self._stdout.println("")
        self._stdout.println("Successfully initialized!")

    #
    # implement IExtensionStateListener
    #

    def extensionUnloaded(self):
        self._stdout.println("Extension was unloaded")

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        print("x", response)
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
        # look for matches of our passive check grep string
        scan_issues = []
        print("1", self._helpers.bytesToString(baseRequestResponse.getResponse()))

        for r in regexes.items():
            regex_name = r[0]
            regex_pattern = r[1]

            regex = re.compile(regex_pattern)
            matches = regex.findall(
                self._helpers.bytesToString(baseRequestResponse.getResponse())
            )

            for match in matches:
                print(match)
                matches = self._get_matches(baseRequestResponse.getResponse(), match)

                if len(matches) == 0:
                    return None

                print(matches)
                # report the issue
                scan_issues.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [
                            self._callbacks.applyMarkers(
                                baseRequestResponse, None, matches
                            )
                        ],
                        "The response contains the <strong>%s</strong> key: <strong>%s</strong> <br><br>found via: <strong>%s</strong> regex."
                        % (regex_name, match, regex_pattern),
                    )
                )
        return scan_issues

    def doActiveScan(self, baseRequestResponse):
        scan_issues = []
        print(
            "1 Active", self._helpers.bytesToString(baseRequestResponse.getResponse())
        )

        for r in regexes.items():
            regex_name = r[0]
            regex_pattern = r[1]

            regex = re.compile(regex_pattern)
            matches = regex.findall(
                self._helpers.bytesToString(baseRequestResponse.getResponse())
            )

            for match in matches:
                print(" Active", match)
                matches = self._get_matches(baseRequestResponse.getResponse(), match)

                if len(matches) == 0:
                    return None

                print(" Active", matches)
                # report the issue
                scan_issues.append(
                    CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [
                            self._callbacks.applyMarkers(
                                baseRequestResponse, None, matches
                            )
                        ],
                        "The response contains the <strong>%s</strong> key: <strong>%s</strong> <br><br>found via: <strong>%s</strong> regex."
                        % (regex_name, match, regex_pattern),
                    )
                )
        return scan_issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL
        # path by the same extension-provided check. The value we return from this
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0


#
# class implementing IScanIssue to hold our custom scan issue details
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
        # pass
        return """
            Sometimes API Keys used within the websites are not properly restricted, or even overprivileged.<br>
            Make sure that you test them manually, to verify that they are used properly according to the documentation.<br><br>
            For example, <a href='https://github.com/streaak/keyhacks' target='_blank'>KeyHacks</a> shows ways in which particular API keys can be used, to check if they are valid.
        """

    def getRemediationBackground(self):
        # pass
        return """
            Read the docs and don't be stupid!
        """

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
