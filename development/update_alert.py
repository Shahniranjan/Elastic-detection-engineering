import requests
import os
import tomllib

url = "https://3bfcfcf60c874cc9a6d955a277f0f6a8.us-central1.gcp.cloud.es.io/api/detection_engine/rules"
api_key = "X1VOTjM1VUJTLW5tSjRLeFhMaEQ6bG5uTXN6dDZRSldPM0xKcENWQ0ViZw=="
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = ""
for root, dirs, files in os.walk("detections/"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            # print(file)
            full_path = os.path.join(root,file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                if alert['rule']['type'] == "query" : # query based alert 
                    required_fields = ['author','description', 'rule_id' ,'name','risk_score', 'severity','type','query']
                elif alert['rule']['type'] == "eql" : # event correlation alert
                    required_fields = ['author','description', 'rule_id', 'name','risk_score', 'severity','type','query','language']
                elif alert['rule']['type'] == "threshold" : # threshold correlation alert
                    required_fields = ['author','description', 'rule_id', 'name','risk_score', 'severity','type','query','threshold']
                else:
                    print("unsupported rule type found in " + full_path) 
                    break;
                
                for field in alert['rule']:
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                             data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n", " ") + "\"," + "\n"
                            if field == 'query':
                             data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\").replace("\"","\\\"").replace("\n", " ") + "\"," + "\n"
                            else:
                             data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n", " ").replace("\"","\\\"") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                        elif type(alert['rule'][field]) == dict:
                            data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace('\'','\"') + "," + "\n"
                data += "  \"enabled\": true\n}"
        rule_id = alert['rule']['rule_id']
        url = url + "?rule_id=" + rule_id
        # print(url)
        elastic_data = requests.put(url, headers=headers, data=data).json()
        print(elastic_data)
