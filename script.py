from burp import IBurpExtender, IHttpListener
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
                print("[!!!] .env file exposed at: " + test_url)
        except Exception as e:
            print("[-] Error checking {}: {}".format(base_url, str(e)))
