import tomllib
import sys
import os

#how to import Toml 
# use known good file C:\Users\shahn\OneDrive\Desktop\Python\Github\detection-rules\rules\windows\collection_email_powershell_exchange_mailbox.toml

# file = "alert_example.toml"

# with open(file,"rb") as toml:
#     alert = tomllib.load(toml)

# for table in alert:
#     for field in alert[table]:
#         print(field)

# for field in alert['rule']:
#     print(field)
failure = 0

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            # print(file)
            full_path = os.path.join(root,file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
               


                present_fields = []
                missing_fields = []
                if alert['rule']['type'] == "query" : # query based alert 
                    required_fields = ['description','rule_id', 'name','risk_score', 'severity','type','query']
                elif alert['rule']['type'] == "eql" : # event correlation alert
                    required_fields = ['description','rule_id', 'name','risk_score', 'severity','type','query','language']
                elif alert['rule']['type'] == "threshold" : # threshold correlation alert
                    required_fields = ['description','rule_id', 'name','risk_score', 'severity','type','query','threshold']
                else:
                    print("unsupported rule type found in " + full_path)
                    break;

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)


                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print("The following fields do not exist in" + file + ": " + str(missing_fields))
                    failure = 1
                else:
                    print("Validation Passed: " + file)

if failure !=0:
     sys.exit(1)
     