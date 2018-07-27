#This script requires python 3
#To run
#python3 scriptname.py
#This script loops through all attack signatures installed and inventories which CVE each signatures protects against. 
#Then it will loop through all policies, determining if it has signatures applied to it that protect against a CVE.
import requests, re
import json, sys
requests.packages.urllib3.disable_warnings() 

#Globals, 
#Configurable globals, should be configured to match your environment
adminUser = 'admin'
adminPass = 'bigip123'
host = 'https://10.4.6.10'
#End configurable globals

signatureCveHash = {}

asmPoliciesPath = '/mgmt/tm/asm/policies'
asmSignaturesPath = '/mgmt/tm/asm/signatures?options=non-default-properties'

asmPoliciesUrl = host + asmPoliciesPath
asmSignaturesUrl = host + asmSignaturesPath

#Require Python v3 or greater
if sys.version_info[:3] < (3,0,0):
    print('requires Python >= 3.0.0')
    sys.exit(1)

#Headers for json payload
restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Get all the asm signatures and the CVE they protect against, store them into a hash
#curl -sk -u admin:pass -X GET https://<bigip>/mgmtm/tm/asm/signatures?options=non-default-properties
asmSignaturesData = requests.get(url=asmSignaturesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
asmSignaturesDataJson = json.loads(asmSignaturesData.text)

#Regex to match cve
cveRegex = '(?P<CVE>[cCvVeE]+\-20\d\d\-\d+)'

#Loop through each signature installed on the system
print("The signatures installed protect against the following CVE")
for signature in asmSignaturesDataJson['items']:

		#CVE are stored in the signature description, search each description of all signatures installed on asm for CVE
		for matchCveRegex in re.finditer(r'([cCvVeE]+\-20\d\d\-\d+)',signature['description'],re.MULTILINE):
		
			matchCveRegexGroups = matchCveRegex.groups()
		
			#If a CVE is found associate it with the signature by storing it in a dictionary
			if matchCveRegexGroups:
	
				signatureCveHash[ str(signature['signatureId']) + ' ' + signature['name']] = matchCveRegexGroups[0]
				print(str(signature['signatureId']) + ' ' + signature['name'] + " " + matchCveRegexGroups[0])

for sigIdName in signatureCveHash:

	print(sigIdName + " " + signatureCveHash[sigIdName])

#Request to get all policies
#curl -sk -u admin:pass -X GET https://<bigip>/mgmtm/tm/asm/policies
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Store all policies data in json format 
asmPoliciesDataJson = json.loads(asmPoliciesData.text)

#Loop through each policy
#curl -sk -u admin:pass -X GET https://<bigip>/mgmt/tm/asm/policies/
for policy in asmPoliciesDataJson['items']:
	
	if (policy['type'] != "parent"):
	
		print("Policy " + policy['name'] + " protects against the following CVE")
				
		#Get the list of signature sets the policy has assigned
		policySignatureSetsListUri = policy['signatureSetReference']['link'].split('https://localhost')[1]
		policySignatureSetsListUriWithHost = host + policySignatureSetsListUri
		
		# curl -sk -u admin:pass -X GET https://<bigip>/mgmt/tm/asm/policies/<policyId>/signature-sets
		policySignatureSetsListData = requests.get(url=policySignatureSetsListUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

		policySignatureSetsListDataJson = json.loads(policySignatureSetsListData.text)
		
		#Get the link/reference to the signature set, so that we can loop through all the signatures
		for signatureSet in policySignatureSetsListDataJson['items']:
			
			policySignatureSetUri = signatureSet['signatureSetReference']['link'].split('https://localhost')[1]
			policySignatureSetUriWithHost = host + policySignatureSetUri
			#curl -sk -u admin:pass -X GET https://<bigip>/mgmt/tm/asm/signature-sets/<signatureSetId>
			policySignatureSetData = requests.get(url=policySignatureSetUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

			policySignatureSetDataJson = json.loads(policySignatureSetData.text)
					
			#Loop through all signatures in the signature set, that are part of the policy
			for signature in policySignatureSetDataJson['signatureReferences']:
							
				policySignatureUri = signature['link'].split('https://localhost')[1]
				policySignatureUriWithHost = host + policySignatureUri
				#curl -sk -u admin:pass -X GET https://<bigip>/mgmt/tm/asm/signatures/<signatureId>
				policySignatureData = requests.get(url=policySignatureUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
				policySignatureDataJson = json.loads(policySignatureData.text)
				
				sigKey = str(policySignatureDataJson['signatureId']) + ' ' + policySignatureDataJson['name']
				
				#And print the ones that have a cve they protect against
				if sigKey in signatureCveHash:
				
					print(str(policySignatureDataJson['signatureId']) + ' ' + policySignatureDataJson['name'] + ' ' + signatureCveHash[sigKey])
			
		print("End of policy " + policy['name'] + " report")
		