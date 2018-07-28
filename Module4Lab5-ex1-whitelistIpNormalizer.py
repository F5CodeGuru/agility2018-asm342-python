#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This script inventories ALL whitelist ip addresses, across all policies and installs all ip across all policies
#This script does not take any other settings into account other than ip and netmask. When the ip is added to the whitelist, it is added with the default settings

import requests
import json, sys, re
requests.packages.urllib3.disable_warnings() 

#Globals, 
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.4.6.10'
#End configurable globals

asmPoliciesPath = '/mgmt/tm/asm/policies/'
applyPolicyUrl = host  + '/mgmt/tm/asm/tasks/apply-policy'

#Require Python v3 or greater
if sys.version_info[:3] < (3,0,0):
    print('requires Python >= 3.0.0')
    sys.exit(1)

#Headers for json payload
restHeaders = {

    'Content-Type': 'application/json'

}

#Global hash/dict to store unique whitelist ip as keys
uniqueWhitelistIpDict = {}

asmPoliciesUrl = host + asmPoliciesPath  

#Request to get all policies
#curl -sk -u admin:pass https://<bigip>/mgmtm/tm/asm/policies
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Store all policies data in json format 
asmPoliciesDataJson = json.loads(asmPoliciesData.text)

#Loop through each policy
#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/
for policy in asmPoliciesDataJson['items']:

	if (policy['type'] != "parent"):

		print("######### Policy: " + policy['name'] + " " + policy['id'])
		policyIdUrl = asmPoliciesUrl +  policy['id'] 

		#Get single policy data
		#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/<policyid>/
		asmPolicyData = requests.get(url=policyIdUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		
		#Load single policy configuration as json
		asmPolicyDataJson = json.loads(asmPolicyData.text)	

		#Loop through the features in a single policy
		for feature in policy:		
				
			#get the whitelist feature
			if feature == 'whitelistIpReference':

					#Get feature name in the uri
					subCollectionLinkAppend = policy[feature]['link'].split("/")[-1]
					#Get the whitelist config
					#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/<policyid>/whitelist-ips
					subCollectionData = requests.get(url=policyIdUrl + '/' + subCollectionLinkAppend,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
					#Store whitelist date in json format
					subCollectionDataJson = json.loads(subCollectionData.text)
													
					#determine if whitelist has at least 1 ip
					if subCollectionDataJson['totalItems'] > 0:
					
						#If ip exists, loop through them and store as key in dictionary to keep them unique
						for item in subCollectionDataJson['items']:
						
							uniqueWhitelistIpDict[item['ipAddress'] + ' ' + item['ipMask']] = 'enabled'

#Loop through the all the policies to determine which whitelist ips are missing and add them
#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/				
for policy in asmPoliciesDataJson['items']:

	if (policy['type'] != "parent"):

		policyIdUrl = asmPoliciesUrl +  policy['id'] 
		#Get single policy data
		#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/<policyId>/
		asmPolicyData = requests.get(url=policyIdUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		#Load single policy configuration as json
		asmPolicyDataJson = json.loads(asmPolicyData.text)	

		#Loop through the features in a single policy
		for feature in policy:					
		
			#get the whitelist feature
			if feature == 'whitelistIpReference':

					subCollectionLinkAppend = policy[feature]['link'].split("/")[-1]
					#Get the whitelist config
					#curl -sk -u admin:pass https://<bigip>/mgmt/tm/asm/policies/<policyid>/whitelist-ips
					subCollectionData = requests.get(url=policyIdUrl + '/' + subCollectionLinkAppend,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
					#Store whitelist date in json format
					subCollectionDataJson = json.loads(subCollectionData.text)		
								
					whitelistIpsUrl = policyIdUrl + '/whitelist-ips/'
					
					#If policy has any whitelist ips, need to figure out which ones and add the missing
					if subCollectionDataJson['totalItems'] > 0:
					
						uniqueWhitelistIpDictTemp = {}
			
						for ip in uniqueWhitelistIpDict:
			
							uniqueWhitelistIpDictTemp[ip] = 0
					
						for item in subCollectionDataJson['items']:
												
							uniqueWhitelistIpDictTemp[item['ipAddress'] + ' ' + item['ipMask']] = '1'
																			
						for ip in uniqueWhitelistIpDictTemp:
												
							if uniqueWhitelistIpDictTemp[ip] == 0:
						
								ipNetmaskList = ip.split(' ')	
								whitelistIpAddBody = '{"ipAddress":"' +  ipNetmaskList[0] + '","ipMask":"' + ipNetmaskList[1] + '"}'
								#curl -sk -u admin:pass -X POST https://<bigip>/mgmt/tm/asm/policies/<policyId>/whitelist-ips -H "Content-Type: application/json" -d '{"ipAddress":"<whitelist ip>", "ipMask":"<netmask>"}' 
								whitelistIpResponse = requests.post(url=whitelistIpsUrl,data=whitelistIpAddBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
								
						applyPolicyBody = '{ "policyReference": {"link":"' + policyIdUrl + '"} }'
						applyPolicyResponse = requests.post(url=applyPolicyUrl,data=applyPolicyBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)			
						
					#If the policy has no ip in the whitelist, add all
					else:
					
						for ip in uniqueWhitelistIpDict:
						
							ipNetmaskList = ip.split(' ')
						
							whitelistIpAddBody = '{"ipAddress":"' +  ipNetmaskList[0] + '","ipMask":"' + ipNetmaskList[1] + '"}'
							#curl -sk -u admin:pass -X POST https://<bigip>/mgmt/tm/asm/policies/<policyId>/whitelist-ips -H "Content-Type: application/json" -d '{"ipAddress":"<whitelist ip>", "ipMask":"<netmask>"}'
							whitelistIpResponse = requests.post(url=whitelistIpsUrl,data=whitelistIpAddBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
					
						applyPolicyBody = '{ "policyReference": {"link":"' + policyIdUrl + '"} }'
						#curl -sk -u admin:pass -X POST https://<bigip>//mgmt/tm/asm/tasks/apply-policy -H "Content-Type: application/json" -d { "policyReference": {"link":"<policyIdUrl>"} }
						applyPolicyResponse = requests.post(url=applyPolicyUrl,data=applyPolicyBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)	
