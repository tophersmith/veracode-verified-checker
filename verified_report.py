import json

class VerifiedReport:
	#Base class for VerifiedReport classes to output the results of a Verified check
	def __init__(self):
		self.failures = {}
		pass

	def add_failure(self, app, check, msg):
		# save the failure in a failure map
		''' 
		Model:
		{
			'AppName': {
				'VerifiedCheckName':[
					'msg1',
					'msg2',
					...
				],
				...
			},
			...
		}
		'''
		app_name = app.name
		check_name = str(check)
		if app_name not in self.failures:
			self.failures[app_name] = {check_name: [msg]}
			return
		checks_list = self.failures[app_name]
		if check_name not in checks_list:
			self.failures[app_name] = {check_name: [msg]}
			return
		self.failures[app_name][check_name].append(msg)
	
	def output(self):
		#expect subclasses to override
		raise Exception('Unimplemented')

class ConsoleReport(VerifiedReport):
	#Write the failures to console
	def __init__(self):
		super().__init__()

	def output(self):
		#print to console in formatted json
		print(json.dumps(self.failures, indent=2))