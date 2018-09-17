import requests

class VirusTotal:
	def __init__(self, API_KEY):
		self.API_KEY       = API_KEY
		self.SCAN_FILE     = 'https://www.virustotal.com/vtapi/v2/file/scan'
		self.REPORT_FILE   = 'https://www.virustotal.com/vtapi/v2/file/report'
		self.DOWNLOAD_FILE = 'https://www.virustotal.com/vtapi/v2/file/download'
		self.GET_COMMENTS  = 'https://www.virustotal.com/vtapi/v2/comments/get'
		self.PUT_COMMENT   = 'https://www.virustotal.com/vtapi/v2/comments/put'

	def ScanFile(self, name):
		params = {'apikey': self.API_KEY}
		payload = {'file': (name, open(name, "rb"))}
		return requests.post(self.SCAN_FILE, files=payload, params=params).json()
	
	def ReportFile(self, resource):
		params = {'apikey': self.API_KEY, 'resource': resource}
		return requests.get(self.REPORT_FILE, params=params).json()
	
	def DownloadFile(self, file_hash):
		params = {'apikey': self.API_KEY, 'hash': file_hash}
		return requests.get(self.DOWNLOAD_FILE, params=params).content

	def GetComments(self, resource):
		params = {'apikey': self.API_KEY, 'resource': resource}
		return requests.get(self.GET_COMMENTS, params=params).text

	def PutComment(self, resource, comment):
		params = {'apikey': self.API_KEY, 'resource': resource, 'comment': comment}
		return requests.post(self.PUT_COMMENT, params=params).json()
