import requests
import platform

def _cls():
	print "\n"*100

def _color(c=None, reset=False):
	if not reset:
		return u"\u001b[38;5;"+str(c)+"m"
	else:
		return u"\u001b[0m"

_BANNER = """

[#+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+#]
[||  ___      ___     ______________         ||]
[||  \;#\    /#;/    {~~~~~~~~~~~~~~}        ||]
[||   \;#\  /#;/           #||#              ||]
[||    \;#  #;/            #||#              ||]
[||      (;;)              ####              ||]
[||                                          ||]
[#+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+#]
"""

_ANSIBANNER = _color(38)+"[#+"+_color(3)+"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"+_color(38)+"+#]\n"+_color(38)+"[||  "+_color(3)+"___      ___     ______________         "+_color(38)+"||]\n"+_color(38)+"[||"+_color(3)+"  \;#\    /#;/    {~~~~~~~~~~~~~~}        "+_color(38)+"||]\n"+_color(38)+"[||"+_color(3)+"   \;#\  /#;/           #||#              "+_color(38)+"||]\n"+_color(38)+"[||"+_color(3)+"    \;#  #;/            #||#              "+_color(38)+"||]\n"+_color(38)+"[||"+_color(3)+"      (;;)              ####              "+_color(38)+"||]\n"+_color(38)+"[||"+_color(3)+"                                          "+_color(38)+"||]\n"+_color(38)+"[#+"+_color(3)+"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"+_color(38)+"+#]"

def _banner(ANSI):
	if ANSI:
		return _ANSIBANNER
	else:
		return _BANNER

class VirusTotal:
	def __init__(self, API_KEY):
		self._API_KEY       = API_KEY
		self._SCAN_FILE     = 'https://www.virustotal.com/vtapi/v2/file/scan'
		self._REPORT_FILE   = 'https://www.virustotal.com/vtapi/v2/file/report'
		self._DOWNLOAD_FILE = 'https://www.virustotal.com/vtapi/v2/file/download'
		self._GET_COMMENTS  = 'https://www.virustotal.com/vtapi/v2/comments/get'
		self._PUT_COMMENT   = 'https://www.virustotal.com/vtapi/v2/comments/put'

	def ScanFile(self, name):
		_params = {'apikey': self._API_KEY}
		_payload = {'file': (name, open(name, "rb"))}
		return requests.post(self._SCAN_FILE, files=_payload, params=_params).json()
	
	def ReportFile(self, resource):
		_params = {'apikey': self._API_KEY, 'resource': resource}
		return requests.get(self._REPORT_FILE, params=_params).json()
	
	def DownloadFile(self, file_hash):
		_params = {'apikey': self._API_KEY, 'resource': file_hash}
		return requests.post(self._DOWNLOAD_FILE, params=_params).content

	def GetComments(self, resource):
		_params = {'apikey': self._API_KEY, 'resource': resource}
		return requests.get(self._GET_COMMENTS, params=_params).text

	def PutComment(self, resource, comment):
		params = {'apikey': self._API_KEY, 'resource': resource, 'comment': comment}
		return requests.post(self._PUT_COMMENT, params=_params).json()

def _HELP(ANSI):
	if ANSI:
		ret = [
			_color(99)+"    home      "+_color(47)+"- "+_color(226)+"Redirect yourself to the home section.",
			_color(99)+"    download  "+_color(47)+"- "+_color(226)+"Redirect yourself to the download section.",
			_color(99)+"    submit    "+_color(47)+"- "+_color(226)+"Redirect yourself to the submit section.",
			_color(99)+"    scan      "+_color(47)+"- "+_color(226)+"Redirect yourself to the scan section.\n",
			_color(99)+"home:",
			_color(226)+"    Redirect yourself to other sections.",
			_color(99)+"download:",
			_color(226)+"    download [file_hash] "+_color(47)+"- "+_color(226)+" Download the file if it is already submitted to VirusTotal. "+_color(196)+"WARNINIG: File could be malicious!",
			_color(226)+"    home                 "+_color(47)+"- "+_color(226)+" Redirect yourself back to the home section.",
			_color(99)+"submit:",
			_color(226)+"    submit [file_path]   "+_color(47)+"- "+_color(226)+" Submit a file to VirusTotal.",
			_color(226)+"    home                 "+_color(47)+"- "+_color(226)+" Redirect yourself back to the home section.",
			_color(99)+"scan:",
			_color(226)+"    scan [resource]      "+_color(47)+"- "+_color(226)+" Scan a file and receive infos.",
			_color(226)+"    home                 "+_color(47)+"- "+_color(226)+" Redirect yourself back to the home section."
			]
		return ret
		
	else:
		ret = [
			"    home      - Redirect yourself to the home section.",
			"    download  - Redirect yourself to the download section.",
			"    submit    - Redirect yourself to the submit section.",
			"    scan      - Redirect yourself to the scan section.\n",
			"home:",
			"    Redirect yourself to other sections.",
			"download:",
			"     download [file_hash] - Download the file if it is already submitted to VirusTotal. WARNING: File could be malicious!",
			"     home                 - Redirect yourself back to the home section.",
			"submit:",
			"    submit [file_path]    - Submit a file to VirusTotal.",
			"    home                  - Redirect yourself back to the home section.",
			"scan:",
			"    scan [resource]       - Scan a file and receive infos.",
			"    home                  - Redirect yourself back to the home section."
			]
		return ret

def _VirusTotalManager(ANSI):
	if ANSI:
		_vt            = _color(34)+"["+_color(38)+"VirusTotal"+_color(34)+"]"+_color(reset=True)
		_ENTER_API_KEY = _vt+_color(99)+": "+_color(3)+"Please enter your API key: "+_color(reset=True)
		_VT_HOME       = _vt+_color(99)+">home~: "+_color(reset=True)
		_VT_DOWN       = _vt+_color(99)+">download~: "+_color(reset=True)
		_VT_SUBMIT     = _vt+_color(99)+">submit~: "+_color(reset=True)
		_VT_SCAN       = _vt+_color(99)+">scan~: "+_color(reset=True)
	else:
		_vt            = "[VirusTotal]"
		_ENTER_API_KEY = ": Please enter your API key: "
		_VT_HOME       = ">home~: "
		_VT_DOWN       = ">download~: "
		_VT_SUBMIT     = ">submit~: "
		_VT_SCAN       = ">scan~: "

	_current = _VT_HOME
	
	_OUTPUT = None
	
	_api_key = raw_input(_ENTER_API_KEY)
	_VT = VirusTotal(_api_key)
	
	while True:
		_cls()
		if _OUTPUT != None:
			print _OUTPUT + "\n"
			_OUTPUT = None
		else:
			print _banner(ANSI)+"\n"
		command = raw_input(_current)
		if command.lower() == "help" or command.lower() == "h" or command == "?":
			_OUTPUT = "\n".join(c for c in _HELP(ANSI))
		
		if _current == _VT_HOME:
			if command.lower() == "download":
				_current = _VT_DOWN
			elif command.lower() == "submit":
				_current = _VT_SUBMIT
			elif command.lower() == "scan":
				_current = _VT_SCAN
		elif _current == _VT_DOWN:
			if command.lower() == "home":
				_current = _VT_HOME
			elif command.split(" ")[0].lower() == "download":
				file_hash = command.split(" ")[1]
				fopen = open(file_hash+".bin", "wb")
				fopen.write(_VT.DownloadFile(file_hash))
				fopen.close()
				_OUTPUT = "[*] Downloaded "+file_hash+".bin"
				print _VT.DownloadFile(file_hash)
		elif _current == _VT_SUBMIT:
			if command.lower() == "home":
				_current = _VT_HOME
			elif command.split(" ")[0].lower() == "submit":
				file_name = " ".join(c for c in command.split(" ")[1:])
				_VT.ScanFile(file_name)
				_OUTPUT = "Reported file "+file_name+"...."
		elif _current == _VT_SCAN:
			if command.lower() == "home":
				_current = _VT_HOME
			elif command.split(" ")[0].lower() == "scan":
				resource = command.split(" ")[1]
				_res = _VT.ReportFile(resource)
				_OUTPUT = "VirusTotal ("+str(_res['positives'])+"):\n"
				for _antivirus in _res['scans']:
					if _res['scans'][_antivirus]['detected']:
						spaces = len(range(20-len(_antivirus)))
						_OUTPUT +=  "    "+_antivirus+": "+" "*spaces+_res['scans'][_antivirus]['result']+"\n"

def _VirusTotalManagerInit():
	_OS = platform.system()
	if _OS.lower() == "linux" or _OS.lower() == "darwin":
		_VirusTotalManager(True)
	else:
		_VirusTotalManager(False)

if __name__ == "__main__":
	_VirusTotalManagerInit()
