# veracode-verified-checker
Simple python script that helps enable users to check their apps for Verified compliance

Run with `python3 verified_check.py [API_KEY] [API_SECRET] [VerifiedChecker]`
- Where API_KEY and API_SECRET are generated from Veracode's UI
- Verified Checker is one of:
  - a - All Verifications are run (for finding which level your applications might match)
  - s - Veracode Standard checks
  - t - Veracode Teams checks
  - c - Veracode Continuous checks

This script can only check things that are accessible from the Veracode API. The script cannot check Security Champion Training, Remediation Guidelines or processes, or Build Integrations/IDE plugins in your environment.


Currently only Veracode Standard is implemented
	-Teams and Continuous TBD

Currently only Console output is supported
	-CSV/Excel/others TBD