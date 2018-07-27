#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This script creates a new asm policy specified in the policyName variable
import requests
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.4.6.10'
asmPoliciesPath = '/mgmt/tm/asm/policies'
policyName="python1"
#End configurable globals

#Host + uri
asmPoliciesUrl = host + asmPoliciesPath

jsonBody = '{"name": "' + policyName + '"}'

#Headers
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Request to create asm policy
#curl -sk -u admin:pass -X POST https://<bigip>/mgmt/tm/asm/policies -d '{"name":"python1"}'
asmPoliciesData = requests.post(url=asmPoliciesUrl,data=jsonBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)


