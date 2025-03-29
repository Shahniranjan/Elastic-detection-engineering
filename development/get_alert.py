import requests
import json

url = "https://3bfcfcf60c874cc9a6d955a277f0f6a8.us-central1.gcp.cloud.es.io/api/detection_engine/rules?rule_id="
id = "e902b9a6-6d17-4cd9-b8c1-a482c33ae2b6"
full_path = url + id

api_key = "X1VOTjM1VUJTLW5tSjRLeFhMaEQ6bG5uTXN6dDZRSldPM0xKcENWQ0ViZw=="
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

elastic_data = requests.get(full_path, headers=headers).json()
print(elastic_data)