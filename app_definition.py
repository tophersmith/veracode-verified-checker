from datetime import datetime

class AppDefinition:
	#Defines the Application basic data and allows adding the findings json later
	
	def __init__(self, json):
		profile = json['profile']
		self.name =profile['name']
		self.guid = json['guid']
		last=json['last_completed_scan_date']
		self.last_scan_time = datetime.strptime(last,'%Y-%m-%dT%H:%M:%S.%fZ') if last != None else None
		self.policy = profile['policies'] if 'policies' in profile else None
		self.findings = None

	def add_findings(self, json):
		if '_embedded' in json:
			self.findings = json['_embedded']['findings']

	def has_findings(self):
		return self.findings != None

	def has_policy(self):
		return self.policy != None
