#This script requires python 3
#To run 
#python3 <scriptname>.py <asm policy name>
#This script takes an asm policy name as an argument and will loop through that policy's signatures and 
# disable staging/"Perform Staging" under Security->Application Security->Attack Signatures->Policy Attack Signature Properties

#Fyi, if you want to see the json output nicely indented, eg
#asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
#print(json.dumps(asmPoliciesData.json(),indent=2))

import requests, re
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals, 
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.4.6.10'
#End configurable globals

asmPoliciesPath = '/mgmt/tm/asm/policies/'
asmSignaturesPath = '/mgmt/tm/asm/signatures?options=non-default-properties'
disableSigStagingJson = '{"performStaging":"false"}'
applyPolicyUrl = host  + '/mgmt/tm/asm/tasks/apply-policy'
policyId = ''

#Content type needed to tell rest server what type of content is being sent
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Url to all policies
asmPoliciesUrl = host + asmPoliciesPath
#Global to save the actual url of the asm policy
asmPolicyIdUrl = ''
#If the policy specified as the argument is found
asmPolicyFoundStatus = 0

#Require Python v3 or greater
if sys.version_info[:3] < (3,0,0):
    print('requires Python >= 3.0.0')
    sys.exit(1)

###Get the name of the policy passed as a command line arg
if len(sys.argv) > 1:

	asmPolicyName=sys.argv[1]
	
else:
    
    print('Error requires asm policy name')
    sys.exit()
##

#Get all asm policies to get the policy id of name passed as the argument
#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Load json output into a python dictionary format
asmPoliciesDataJson = json.loads(asmPoliciesData.text)

#Loop through each policy to find which one equals the command line argument
for policy in asmPoliciesDataJson['items']:
	
	#Check to find the policy 
	if (policy['name'] == asmPolicyName):
		
		#If found
		asmPolicyFoundStatus = 1
		policyId =  policy['id'] 
		
		asmPolicyIdUrl = asmPoliciesUrl + policy['id']
		asmPolicySignaturesUrl = asmPoliciesUrl + policy['id'] + '/signatures/'
		
		#Get the policy's signatures
		#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy>
		asmPolicySignatureData = requests.get(url=asmPolicySignaturesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		asmPolicySignatureDataJson = json.loads(asmPolicySignatureData.text)
		
		#Loop through each signature, disbaling the performStaging variable
		for policySig in asmPolicySignatureDataJson['items']:
		
			#curl -sk -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures?options=non-default-properties
			asmPolicySignatureUrl = asmPolicySignaturesUrl + policySig['id']
			
			#curl -sk -X PATCH -u admin:<pass> https://<bigip>/mgmt/tm/asm/policies/<policyId>/signatures/<sigId in policy> -d '{"performStaging":"false"}' -H '"Content-Type":"application/json"'
			asmPolicySigResult = requests.patch(url=asmPolicySignatureUrl,data=disableSigStagingJson,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#If the policy name was not found, exit						
if asmPolicyFoundStatus == 0:

		sys.exit("No policy by that name found")

#Apply the policy if it was found
else: 

	#curl -sk -X POST -u admin:<pass> https://<bigip>/mgmt/tm/asm/tasks/apply-policy-d '{ "policyReference": {"link":"https://<bigip>/mgmt/tm/asm/policies/<policyId>"} ' -H '"Content-Type":"application/json"'
	applyPolicyBody = '{ "policyReference": {"link":"' + asmPolicyIdUrl + '"} }'
	applyPolicyResponse = requests.post(url=applyPolicyUrl,data=applyPolicyBody,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
	
	
	