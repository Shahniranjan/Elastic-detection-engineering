import requests
import json

url = "https://3bfcfcf60c874cc9a6d955a277f0f6a8.us-central1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = """
{
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "interval": "1h", 
  "name": "MS Office child process testing",
  "severity": "low",
  "tags": [
   "child process",
   "ms office"
   ],
  "type": "query",
  "from": "now-70m", 
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "language": "kuery",
  "filters": [
     {
      "query": {
         "match": {
            "event.action": {
               "query": "Process Create (rule: ProcessCreate)",
               "type": "phrase"
            }
         }
      }
     }
  ],
  "required_fields": [
    { name: "process.parent.name", "type": "keyword" }
  ],
  "related_integrations": [
    { "package": "o365", "version": "^2.3.2"}
  ],
  "enabled": true
}
"""
print (data)
elastic_data = requests.post(url, headers=headers, data=data).json()
