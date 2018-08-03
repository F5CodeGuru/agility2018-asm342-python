#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This script add an ip to the whitelist and applies the policy
import requests
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'password'
host = 'https://10.1.1.245'
asmPoliciesPath = '/mgmt/tm/asm/policies/'
applyPolicyUrl = host  + '/mgmt/tm/asm/tasks/apply-policy'

#Policy to add the whitelist ip to
policyName="python1"

#Filter on the policy specified and the display on its id
asmPoliciesPathFilter = asmPoliciesPath + '?$filter=name+eq+' +  policyName + '&$select=id'

#Json body to add whitelist ip
whitelistIpAddBody = '{"ipAddress":"192.168.1.5","ipMask":"255.255.255.255"}'
#End configurable globals

#Host + uri
asmPoliciesUrl = host + asmPoliciesPath
asmPoliciesUrlFilter = host + asmPoliciesPathFilter

#Headers
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Request to get policy data
#curl -sk -u admin:pass https://<bigip>/mgmtm/tm/asm/policies
asmPoliciesData = requests.get(url=asmPoliciesUrlFilter,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Store policy data in json format 
asmPoliciesDataJson = json.loads(asmPoliciesData.text)

#Get policy id
policyId = asmPoliciesDataJson['items'][0]['id']
#Use policy id to build policy url
policyIdUrl = asmPoliciesUrl + policyId

#Request to create asm policy
#curl -sk -u admin:pass -X POST https://<bigip>/mgmt/tm/asm/policies -d '{"name":"python1"}'
whitelistIpsUrl = policyIdUrl + '/whitelist-ips/'
#curl -sk -u admin:pass -X POST https://<bigip>/mgmt/tm/asm/policies/<policyId>/whitelist-ips -H "Content-Type: application/json" -d '{"ipAddress":"<whitelist ip>", "ipMask":"<netmask>"}'
whitelistIpResponse = requests.post(url=whitelistIpsUrl,data=whitelistIpAddBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

applyPolicyBody = '{ "policyReference": {"link":"' + policyIdUrl + '"} }'
#curl -sk -u admin:pass -X POST https://<bigip>//mgmt/tm/asm/tasks/apply-policy -H "Content-Type: application/json" -d { "policyReference": {"link":"<policyIdUrl>"} }
applyPolicyResponse = requests.post(url=applyPolicyUrl,data=applyPolicyBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)	
