from datetime import datetime
from pprint import pprint

class VerifiedCheck:
	#Base class for VerifiedCheck classes to confirm app compliance with Verified levels
	def __init__(self, app, policies_dict):
		self.app = app
		self.policies_dict = policies_dict

	def do_check(self, report):
		#expect subclasses to override
		raise Exception('Unimplemented')

	def __str__(self):
		#Uses classname, used in reporting
		return self.__class__.__name__

class VerifiedStandard(VerifiedCheck):
	'''
	Standard:
		Apps are policy scanned for static analysis
		No VHighs
		Scanned at least every 6 months
	'''
	def __init__(self, app, policies_dict):
		super().__init__(app, policies_dict)
		'''6 months in days-ish'''
		self.standard_min_days = 180

	def do_check(self, report):
		self.check_vhighs(report)
		self.check_date(report)
		self.check_policy(report)
	
	def check_vhighs(self, report):
		#Examine app findings for unclosed, very high severity, static findings
		if self.app.has_findings():
			vhigh = 0
			for finding in self.app.findings:
				if (finding['finding_status']['status'] != 'CLOSED' and 
					finding['finding_details']['severity'] == 5 and 
					finding['scan_type'] == 'STATIC'):
					vhigh = self.vhigh + finding['count'] 
			if vhigh > 0:
				report.add_failure(self.app, self, 'Must have no Very High vulnerabilities. Has %d vulnerabilities' % (vhigh))
	
	def check_date(self, report):
		#Check app's last scan time to ensure it is within the allowed timeline
		days_since = (datetime.now() - self.app.last_scan_time).days if self.app.last_scan_time != None else None
		if days_since == None:
			report.add_failure(self.app, self, 'Must have been scanned in the last %d days. Has never been scanned' % (self.standard_min_days))
		elif days_since > self.standard_min_days:
			report.add_failure(self.app, self, 'Must have been scanned in the last %d days. Last Scan was %d days ago' % (self.standard_min_days, days_since))

	def check_policy(self, report):
		#Check that the app's policy is known, and is configured to scan static analysis at most every 6 months
		'''
		NOTE THIS DOES NOT CHECK IF THE POLICY PASSED. 
		The other rules check for policy function, but if a customer chooses to have a strict policy that is 
		over-and-above the Standard policy requirements, they app succeeds Verified, but fails the policy
		'''
		if self.app.has_policy():
			for policy in self.app.policy:
				policy_name = policy['name']
				if policy_name not in self.policies_dict:
					report.add_failure(self.app, self, 'Unknown Policy "%s" attached to Application "%s"' % (policy_name, self.app.name))
				else:
					policy_rules = self.policies_dict[policy_name]['finding_rules']
					found_policy = None
					for policy_rule in policy_rules:
						scan_type = policy_rule['scan_type']
						finding_type = policy_rule['type']
						if ('STATIC' in scan_type or 'ANY' in scan_type and 
							finding_type != 'FAIL_ALL' or finding_type != 'MAX_SEVERITY'):
							found_policy = True
					if not found_policy:
						report.add_failure(self.app, self, 
							'No Policies attached to Application "%s" are configured to block for Static Analysis/Any Analysis and Very High findings' % (self.app.name))

class VerifiedTeam(VerifiedCheck):
	def __init__(self, app):
		raise Exception('Not Implemented')

class VerifiedContinuous(VerifiedCheck):
	def __init__(self, app):
		raise Exception('Not Implemented')
