#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This scriptgets the specified ASM policy and outputs its configuration in json format
import requests
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals, 
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://29.4.6.19'
asmPoliciesPath = '/mgmt/tm/asm/policies?$filter=name+eq+python1'
#End configurable globals

#Host + uri
asmPoliciesUrl = host + asmPoliciesPath

#Headers
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Request to get all policies
#curl -sk -u admin:pass https://<bigip>/mgmtm/tm/asm/policies
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Print pretty
print(json.dumps(asmPoliciesData.json(),indent=2))

