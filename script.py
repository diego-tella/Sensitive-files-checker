from burp import IBurpExtender, IHttpListener, IScanIssue
from java.net import URL
import threading

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sensitive files checker")
        callbacks.registerHttpListener(self)
        print("[*] Sensitive files checker installed!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            base_url = "{}://{}".format(url.getProtocol(), url.getHost())

            if not hasattr(self, 'checked'):
                self.checked = set()

            if base_url not in self.checked:
                self.checked.add(base_url)
                #print("[*] Checking for exposed .git on: " + base_url)
                threading.Thread(target=self.check_git, args=(base_url,)).start()
                threading.Thread(target=self.check_dotenv, args=(base_url,)).start()

    def check_git(self, base_url):
        try:
            test_url = base_url + "/.git/HEAD"
            url_obj = URL(test_url)
            
            port = url_obj.getPort()
            if port == -1:
                port = 443 if url_obj.getProtocol() == "https" else 80
            
            service = self.helpers.buildHttpService(url_obj.getHost(), port, url_obj.getProtocol())

            req = self.helpers.buildHttpRequest(url_obj)
            response = self.callbacks.makeHttpRequest(service, req)

            resp_info = self.helpers.analyzeResponse(response.getResponse())
            status_code = resp_info.getStatusCode()
            body = response.getResponse()[resp_info.getBodyOffset():].tostring()

            if status_code == 200 and "ref:" in body:
                issue = CustomScanIssue(
                    httpService=service,
                    url=url_obj,
                    requestResponse=response,
                    name=".git exposed found!",
                    detail="A .git directory is exposed at " + test_url,
                    severity="Medium"
                )
                self.callbacks.addScanIssue(issue)
                print("[!!!] .git directory exposed at: " + test_url)
                   
        except Exception as e:
            print("[-] Error checking {}: {}".format(base_url, str(e)))

    def check_dotenv(self, base_url):
        try:
            test_url = base_url + "/.env"
            url_obj = URL(test_url)
            
            port = url_obj.getPort()
            if port == -1:
                port = 443 if url_obj.getProtocol() == "https" else 80
            
            service = self.helpers.buildHttpService(url_obj.getHost(), port, url_obj.getProtocol())

            req = self.helpers.buildHttpRequest(url_obj)
            response = self.callbacks.makeHttpRequest(service, req)

            resp_info = self.helpers.analyzeResponse(response.getResponse())
            status_code = resp_info.getStatusCode()

            if status_code == 200:
                issue = CustomScanIssue(
                    httpService=service,
                    url=url_obj,
                    requestResponse=response,
                    name=".env exposed found!",
                    detail="A .env file is exposed at " + test_url,
                    severity="Medium"
                )
                self.callbacks.addScanIssue(issue)
                print("[!!!] .env file exposed at: " + test_url)
        except Exception as e:
            print("[-] Error checking {}: {}".format(base_url, str(e)))


class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, requestResponse, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._requestResponse]

    def getHttpService(self):
        return self._httpService
