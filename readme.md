# Nessus Reporting Scripts

I love nessus. But their default export options are a bit lacking. The CVS exports, especially for compliance reports, are full of data people don't want. So I made some scripts to convert .nessus files into the kinds of spreadsheets my admins want to see.

##nessus_vuln.rb
Usage: ./nessus_vuln.rb scan.nessus scanreport.xls
This is for standard vulnerability scans. It edits out any compliance findings in case you are mixing and matching you scans and splits out the rests and puts each severity in it's own tab. Info or risk of none are not stored.

##nessus_compliance.rb
Usage: ./nessus_compliance.rb audit.nessus auditreport.xls
This is to deal with audit reports, I use the CIS audit files and I have not tested this on anything other than the CIS audit files. All of the compliance findings are stored in three tabs, failed, error, and warning. Failed are the ones that didn't match the CIS standard, error and warnings may be issues or might not be and need to be more manually followed up on. Passed items are ditched.

**Notes:** The files are pretty simple and you should be able to edit them to meet your needs if you say, want passed or info items, or everythign in one tab, etc. Also I'm a bit rusty on my Ruby and the formating section looks very bad from a Ruby pont of view, way too much copy and paste. I know there should be a better way to do that and make it just a few lines of code but I didn't figure it out and this was faster. I'll take cleanup or optimization pull requests if it hurts your head. Also I tested the vuln script on a very, very large .nessus file. It worked fine and was rather quick, for a single threaded ruby script anyway.