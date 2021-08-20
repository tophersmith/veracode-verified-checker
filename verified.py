import sys
import json
import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
from pprint import pprint
from datetime import datetime
from app_definition import AppDefinition
from verified_check import VerifiedStandard, VerifiedTeam, VerifiedContinuous
from verified_report import VerifiedReport, ConsoleReport
from pprint import pprint

url_base = 'https://api.veracode.com/appsec'

min_severity = 3 # findings api only returns medium + 

def main():
	if len(sys.argv) != 4:
		print('Usage: [API Key] [API Secret Key] [Check Type s=Standard t=Team c=Continuous a=All]')
		exit(1)

	auth = RequestsAuthPluginVeracodeHMAC(api_key_id=sys.argv[1],
										  api_key_secret=sys.argv[2])
	'''
	Process:
		Make Veracode Verified Checks class
		Make reporter
		Get all policies
		Get all apps
		For each app
			Get findings for the app
			Check the app + policies based on the Verified level
			Report any failures from the Verified Checks
	'''
	try:
		checks = make_checks(sys.argv[3])
		report = ConsoleReport()
		policies_dict = get_policies_dict(auth)
		apps_list = get_applications_list(auth)
		apps_size = len(apps_list)
		print('%d apps found' % (apps_size))
		count = 1
		for app in apps_list:
			print('Checking %s (%d/%d)' % (app.name, count, apps_size))
			add_findings_to_app(auth, app)
			check(app, policies_dict, report, checks)
			count = count + 1
		report.output()
	except Exception as e:
		print('Error while scanning or uploading. ' + str(e))
		raise e

def get_policies_dict(auth):
	#Get all policies available to the user as a dict of 'policy_name': 'policy_json'
	done = False
	policies = {}
	page_count = 0
	while not done:
		r = requests.get(url_base + '/v1/policies', auth=auth, params={'size':500, 'page': page_count})
		if not r.ok:
			print(r.text)
			raise Exception('ERROR: Received status code %s while trying to get applications' % r.status_code)
		#Check pagination
		total_pages = r.json()['page']['total_pages']
		page_count = page_count + 1
		if page_count == total_pages:
			done = True
		
		policies.update({policy['name']:policy for policy in r.json()['_embedded']['policy_versions']})
	return policies

def make_checks(check_type):
	#Create the Verified Check class for the given check_type
	cases = {'s': [VerifiedStandard],
			 't': [VerifiedTeam],
			 'c': [VerifiedContinuous],
			 'a': [VerifiedStandard,VerifiedTeam, VerifiedContinuous]}
	if check_type in cases:
		return cases[check_type]
	else:
		raise Exception('Unknown case. Must be one of %s' % ( ', '.join(cases.keys()) ))

def get_applications_list(auth):
	#Get all applications
	done = False
	apps_list = []
	page_count = 0
	while not done:
		r = requests.get(url_base + '/v1/applications', auth=auth, params={'size':500, 'page':page_count})
		if not r.ok:
			print(r.text)
			raise Exception('ERROR: Received status code %s while trying to get applications' % r.status_code)
		#Check pagination
		total_pages = r.json()['page']['total_pages']
		page_count = page_count + 1
		if page_count == total_pages:
			done = True

		apps_list.extend([AppDefinition(application) for application in r.json()['_embedded']['applications']])
	return apps_list

def add_findings_to_app(auth, app):
	#Add the findings json to the app
	r = requests.get(url_base + ('/v2/applications/%s/findings' % app.guid), auth=auth, params={'severity_gte': min_severity})
	if not r.ok:
		print(r.text)
		raise Exception('ERROR: Received status code %s while trying to get findings' % r.status_code)
	app.add_findings(r.json())

def check(app, policies_dict, report, checks):
	#Using the Verified Check, check the app + policies
	for check_func in checks:
		check = check_func(app, policies_dict)
		check.do_check(report)

if __name__ == '__main__':
	sys.exit(main())