# VirusTotalAPI

This is a VirusTotal API written in python

usage:
  1. Put this file in your project-directory
  2. Create a new VirusTotal Object with your VirusTotal API key, which you can find on your VirusTotal profile

Functions and parameters of the VirusTotal class:

/s
 FUNCTION   | PARAMETERS                      | RETURN
 ScanFile     path of your file                 JSON
 ReportFile   resource (e.g. hash)              JSON
 DownloadFile resource (e.g. hash)              BYTES
 GetComments  resource (e.g. hash)              TEXT
 PutComment   resource (e.g. hash) / comment    JSON

