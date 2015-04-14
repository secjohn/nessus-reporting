# Nessus Reporting Scripts

I love nessus. But their default export options are a bit lacking. The CVS exports, especially for compliance reports, are full of data people don't want. So I made some scripts to convert .nessus files into the kinds of spreadsheets my admins want to see.

##nessus_vuln.rb
Usage: ./nessus_vuln.rb scan.nessus scanreport.xls
This is for standard vulnerability scans. It edits out any compliance findings in case you are mixing and matching you scans and splits out the rests and puts each severity in it's own tab. 

Update 04/14/2015: It no longer ignores the informational ones. Instead it puts them in their own hash called @scaninfo to be used as needed. Trying to spit all of them out into Excel on a large scan seems to corrupt the excel file, so everything can't be used but some info is valuable. What is used so far is:
A tab showing if authentication failed so local checks were not performed, this is handy when doing authenticated scans.
A tab showing the local admin accounts. The way I have it setup is to delete the standard ones for my enviornment and only show the non-standard ones. If you want to use this you will need to update the temp.sub! lines with your data. I suggest starting by simply commenting out the whole loop that does that and dumping all the local admin data first then see what you want to strip out.
If you have more uses for the informational findings the data is in @scaninfo to use, if you have requests let me know.

##nessus_compliance.rb
Usage: ./nessus_compliance.rb audit.nessus auditreport.xls
This is to deal with audit reports, I use the CIS audit files and I have not tested this on anything other than the CIS audit files. All of the compliance findings are stored in three tabs, failed, error, and warning. Failed are the ones that didn't match the CIS standard, error and warnings may be issues or might not be and need to be more manually followed up on. Passed items are ditched.

####Requirnments: 
Ruby 1.9
ruby-nessus and spreadsheet gems
Currently the ruby-nessus gem doesn't appear to work on Ruby 2 and I haven't looked into it. If you look at it https://github.com/mephux/ruby-nessus z3n0wl has some cool pull requests that never got added, I need to look into those. The exploit_available feature is nice. Currently I'm not using it.

**Notes:** The files are pretty simple and you should be able to edit them to meet your needs if you say, want passed or info items, or everythign in one tab, etc. 

