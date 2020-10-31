import urllib.request
import urllib.error
import os
import filecmp
import shutil
# import twython
import yaml
from skimage.metrics import structural_similarity
import cv2
import ssl

'''
>>> TO DO  <<<
Immediate: Tweet images
Short term: Compare screenshot of PhishSite and Correct site,  clean up/refactor, documentation
Medium term: Archiving site data by changes since last run
Long term: Add new main sites automatically based on permutations of known good, Add new subsites from robots.txt, 


ToDo:
Initialise the screenshots for the clients (known good groups)
Fix the screenshot system
Clean up the code

Dynamically generate the list of possible phishing site
use DNS twist to find out if the site is active

Process URL subProgram, convers main+extra URL  to  the generic format

Archiving, changing the old file to a different a different date 


FAR FAR AWAY: Multi organisation support,

'''

DEBUG = 0

HOST_TO_PHISH="fullPhishList.yaml"
PHISH_SITE_LIST_YAML="phishList.yaml"
ALERT_KEYWORDS="keywords.yaml"



# downloads a website
def downloadFile(fileDirectory,mainURL, extraURL=""):


	if not os.path.exists(fileDirectory+"/"+mainURL):
		os.makedirs(fileDirectory+"/"+mainURL)

	# Grabbing the actual information from the site
	reponse=urllib.request.urlopen("http://"+mainURL+"/"+extraURL)
	data=reponse.read()

	# branching path related to if the URL has the extension bit or not
	# File path is <new|old>/<mainURL>/<mainURL|extraURL>
	# The idea is this can then be expanded to have folder created per day and then archived
	if extraURL == "":
		with open(fileDirectory+"/"+mainURL+ "/" + mainURL, "wb+") as testFile:
			testFile.write(data)

	else:
		with open(fileDirectory+"/"+mainURL+ "/" + extraURL, "wb+") as testFile:
			testFile.write(data)
			


# checskt to see if a directory/file exists
def doesExist(fileDirectory, file):
	#Checks to make sure that a file exists 
	if os.path.exists(fileDirectory+"/"+file):
		return True
	else:
		return False


# checks to see if two files are the same where the files patch the mainURL and extraURL
# returns if TRUE/FALSE for is matching
def compareFile(fileDirectory1, fileDirectory2, mainURL, extraURL=""):
	# initialising so that if the file doesn't exist then it will return false and raise an alert
	isMatching = False
	#Different URL different files
	if extraURL == "":
		#Makes sure that both files exist
		if doesExist(fileDirectory1, mainURL+"/"+mainURL) & doesExist(fileDirectory2, mainURL+"/"+mainURL):
			#compares the files if both files exist
			isMatching = filecmp.cmp(fileDirectory1+"/"+mainURL+ "/" + mainURL, fileDirectory2+"/"+mainURL+ "/" + mainURL)
			
	else:
		if doesExist(fileDirectory1, mainURL+"/"+extraURL) & doesExist(fileDirectory2, mainURL+"/"+extraURL):
			isMatching = filecmp.cmp(fileDirectory1+"/"+mainURL+"/"+extraURL, fileDirectory2+"/"+mainURL+"/"+extraURL)

	return isMatching



#Moves a file from source to destinat where the file name is based on URL
# returns Nothing
def moveFile(source, dest, mainURL, extraURL=""):
	#moves a file from the source to the dest following the URL naming scheme
	#Makes the dest if it doesn't already exist
	if not os.path.exists(dest):
		os.makedirs(dest)

	if not os.path.exists(dest+"/"+mainURL):
		os.makedirs(dest+"/"+mainURL)

	if extraURL=="":
		shutil.move(source+"/"+mainURL+"/"+mainURL,dest+"/"+mainURL+"/"+mainURL)
	else:
		shutil.move(source+"/"+mainURL+"/"+extraURL,dest+"/"+mainURL+"/"+extraURL )



# returns a list of the keys in a yaml file 
def yamlKeyList(yamlFile):
	# collects the keys (main sites) from the config YAML
	with open(yamlFile) as file:
	    documents = yaml.full_load(file)
	    return documents.keys()


# returns a list of the contents based on the key
def yamlKeyContentList(key, yamlFile):
	# Returns the matching sub values based on a given main value
	with open(yamlFile) as file:
		documents = yaml.full_load(file)
		for item, doc in documents.items():
			if item == key:
				return doc


				'''
				if doc != [None]:
					return doc
				else:
					return [""]
				'''


# Place holder for processing an alert, this can be converted/carved out  to piping to splunk or  twitter
# can be converted to evaluatePhish as  this process only runs when a website changes you can
# then use this subPrgram to determine if a proper alert should be raised
# IE an alert can be raised if text similary or image similarity is above a certain threshhold
def raiseAlert(currDir, screenDir, mainURL, extraURL, hostSite, fileName):
	print("---< ALERT >---")
	print("--------")
	print("alert raised for: "+mainURL+"/"+extraURL)
	print("Matching site: "+hostSite)
	print("--------")	


# evaluates if the phishing site has changed
def evaluateSiteDiff(newDir, oldDir, screenDir, mainURL, extraURL, hostSite):
	
	# Fixing formating to avoid issues with handing arrays with 0 elements
	if extraURL == [""]:
		extraURL = ""

	# If 
	if extraURL== "":
		fileName = mainURL
	else:
		fileName = extraURL

	downloadFile(newDir,mainURL, extraURL)

	
	if not compareFile(newDir, oldDir, mainURL, extraURL):
		if DEBUG:
			print("not the same  www."+mainURL+"/"+extraURL+"/")
		
		raiseAlert(newDir, screenDir, mainURL, extraURL, hostSite, fileName)



		# moves the file elsewhere
		moveFile(newDir, oldDir,mainURL, extraURL)
	elif DEBUG:
		print("shit matching bro www."+mainURL+"/"+extraURL+"/")


def main():
	# new directory is where the files will be downloaded to temporarily
	# old directory is where the 2nd most recent copy is
	# screenShot is 
	newDirectory = "new"
	oldDirectory = "old"
	screenshot="screenshot"
	ssl._create_default_https_context = ssl._create_unverified_context

	# the list of all the good sites mapped to the list of doubt sites
	hostList = yamlKeyList(HOST_TO_PHISH)
	if DEBUG:
		print("hostlist == "  + str(hostList))
	for hostSite in hostList:

		# the list of known bad sites based on the host their connected to
		phishSiteList = yamlKeyContentList(hostSite, HOST_TO_PHISH)
		if DEBUG:
			print("phishSiteList == " + str(phishSiteList))

		for phishSite in phishSiteList:

		# the list of all sub sites connected to the main sitet
			subPhishList = yamlKeyContentList(phishSite, PHISH_SITE_LIST_YAML)
			if DEBUG:
				print("subPhishList == " + str(subPhishList))

			for subPhishSite in subPhishList:
				evaluateSiteDiff(newDirectory, oldDirectory, screenshot, phishSite, subPhishSite, hostSite)






if __name__ == "__main__":
    # execute only if run as a script
    main()

