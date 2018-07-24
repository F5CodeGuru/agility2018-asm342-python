import requests, re
import json, sys
requests.packages.urllib3.disable_warnings() 

#https://10.4.6.10/mgmt/toc
#Globals, should be configured to match your environment
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

restHeaders = {

    'Content-Type': 'application/json; charset=UTF-8'

}

#Get all the asm signatures and the CVE they protect against, store them into a hash
asmSignaturesData = requests.get(url=asmSignaturesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
asmSignaturesDataJson = json.loads(asmSignaturesData.text)

cveRegex = '(?P<CVE>[cCvVeE]+\-20\d\d\-\d+)'
#cveRegex = '(?P<CVE>CVE)'


for signature in asmSignaturesDataJson['items']:

		for matchCveRegex in re.finditer(r'([cCvVeE]+\-20\d\d\-\d+)',signature['description'],re.MULTILINE):
		
			matchCveRegexGroups = matchCveRegex.groups()
		
			if matchCveRegexGroups:
	
				#print(signature['id'] + ' ' + str(signature['signatureId']) + ' ' + signature['name'] + matchCveRegex.group('CVE'))
				signatureCveHash[ str(signature['signatureId']) + ' ' + signature['name']] = matchCveRegexGroups[0]
				print(str(signature['signatureId']) + ' ' + signature['name'] + " " + matchCveRegexGroups[0])
			
#Worked excpet only got first match
#for signature in asmSignaturesDataJson['items']:

#		matchCveRegex = re.search(cveRegex,signature['description'],re.MULTILINE)
		
#		if matchCveRegex:
	
			#print(signature['id'] + ' ' + str(signature['signatureId']) + ' ' + signature['name'] + matchCveRegex.group('CVE'))
#			signatureCveHash[ str(signature['signatureId']) + ' ' + signature['name']] = matchCveRegex.group('CVE')
			
##asmPolicySignaturesData = requests.get(host + '/mgmt/tm/asm/policies/VJ9R7fv0LGT3klkKo-50tA/signatures/yphzeMudy8K5R6jScHzTRg?ver=13.1.0',headers=restHeaders,auth=(adminUser,adminPass),verify=False)
##print(json.dumps(asmPolicySignaturesData.json(),indent=2))
for sigIdName in signatureCveHash:

	print(sigIdName + " " + signatureCveHash[sigIdName])

#get listing of all ASM policies

#Http connection
asmPoliciesData = requests.get(url=asmPoliciesUrl,headers=restHeaders,auth=(adminUser,adminPass),verify=False)

#Print pretty
#print(json.dumps(asmPoliciesData.json(),indent=2))

asmPoliciesDataJson = json.loads(asmPoliciesData.text)

for policy in asmPoliciesDataJson['items']:
	
	if (policy['type'] != "parent"):
	
		print("Policy " + policy['name'] + " protects against the following CVE")
				
		#Get the list of signature sets the policy has assigned
		policySignatureSetsListUri = policy['signatureSetReference']['link'].split('https://localhost')[1]
		policySignatureSetsListUriWithHost = host + policySignatureSetsListUri
		
		policySignatureSetsListData = requests.get(url=policySignatureSetsListUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		#print(json.dumps(policySignatureSetsListData .json(),indent=2))


		policySignatureSetsListDataJson = json.loads(policySignatureSetsListData.text)
		
		#Get the link/reference to the signature set, so that we can loop through all the signatures
		for signatureSet in policySignatureSetsListDataJson['items']:
		
			#print("Item#####   ")
			#print(signatureSet['signatureSetReference']['link'])
			
			
			policySignatureSetUri = signatureSet['signatureSetReference']['link'].split('https://localhost')[1]
			policySignatureSetUriWithHost = host + policySignatureSetUri
			#print(policySignatureSetUriWithHost)
			policySignatureSetData = requests.get(url=policySignatureSetUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
			#print(json.dumps(policySignatureSetData .json(),indent=2))

			policySignatureSetDataJson = json.loads(policySignatureSetData.text)
			
			#print(policySignatureSetDataJson)
			
			for signature in policySignatureSetDataJson['signatureReferences']:
			
				
				policySignatureUri = signature['link'].split('https://localhost')[1]
				policySignatureUriWithHost = host + policySignatureUri
		
				policySignatureData = requests.get(url=policySignatureUriWithHost,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
				policySignatureDataJson = json.loads(policySignatureData.text)
				#print(policySignatureDataJson)
				
				sigKey = str(policySignatureDataJson['signatureId']) + ' ' + policySignatureDataJson['name']
				
				if sigKey in signatureCveHash:
				
					print(str(policySignatureDataJson['signatureId']) + ' ' + policySignatureDataJson['name'] + ' ' + signatureCveHash[sigKey])
			
			#print(json.dumps(item.json(),indent=2))
		print("End of policy " + policy['name'] + " report")
		
		#subCollectionLinkAppend = policy[feature]['link'].split("/")[-1]
					#subCollectionData = requests.get(url=policyIdUrl + '/' + subCollectionLinkAppend,headers=restHeaders,auth=(adminUser,adminPass),verify=False)
		
		#Then loop through signatures per  policy
		#curl -k -X GET -u admin:bigip123  https://10.4.6.10//mgmt/tm/asm/policies/MrLpFzRHNarvj_zuAOD0fw/signatures?options=non-default-properties | jq

	#	if policy['enforcementMode'] == "blocking":

	#		print(policy['name'] + " ->  assigned virtual server(s): " , end='')
		
	#		for virtual in policy['virtualServers']:
		
	#			print(virtual + " ",end='')