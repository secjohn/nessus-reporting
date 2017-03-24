#!/usr/bin/env ruby

require 'rubygems'
require 'nessus'
require 'spreadsheet'

#Usage and help.
unless ARGV[0] and ARGV[1]
  puts "Usage nessus_vuln.rb name.nessus output.xls (must be xls not xlsx)"
  puts "To skip failed local checks and non-standard local admins add nlc as the third argument, nessus_vuln.rb name.nessus output.xls nlc"
  puts "This script takes a .nessus file and edits out any compliance findings and ones with no risk and splits the others out in tabs sorted by host."
  puts "admins.txt file is for approved local admins, domain name and groups need to be edited in the script."
  exit 1
end

#Opening the .nessus file and sorting the data
@scandata = Hash.new
@scaninfo = Hash.new
@event_num = 1
@info_num = 1
Nessus::Parse.new(ARGV[0]) do |scan|
scan.each_host do |host|
host.each_event do |event|
  unless event.name.include? "Compliance"
    if event.informational?
      @scaninfo.update( @info_num => {ip: "#{host.ip}", hostname: "#{host.hostname}", sevwords: "#{event.severity.in_words}", port: "#{event.port}", name: "#{event.name}", synopsis: "#{event.synopsis}", description: "#{event.description}", solution: "#{event.solution}", cve: "#{event.cve}", plugin_id: "#{event.plugin_id}", plugin_output: "#{event.plugin_output}"})
      @info_num += 1 
      else 
    @scandata.update( @event_num => {ip: "#{host.ip}", hostname: "#{host.hostname}", sevwords: "#{event.severity.in_words}", port: "#{event.port}", name: "#{event.name}", synopsis: "#{event.synopsis}", description: "#{event.description}", solution: "#{event.solution}", cve: "#{event.cve}", plugin_id: "#{event.plugin_id}", plugin_output: "#{event.plugin_output}"})
    @event_num += 1
  end
  end
end
end
end


#Setting up arrays to dump into the spreadsheet and putting the data in them
@critical = []
@high = []
@medium = []
@low = []
@flc = []
@ladmin =[]
@ladminh = Hash.new
@critcount = []
@ipcount = []
@flccount = []
@ladmincount = []

@scandata.each do |key, value|
  if @scandata[key].has_value?("Critical Severity")
    @critical<< @scandata[key].values 
    @critcount<< @scandata[key][:ip]
  end
  if @scandata[key].has_value?("High Severity")
    @high<< @scandata[key].values 
    @critcount<< @scandata[key][:ip]
  end
  @medium<< @scandata[key].values if @scandata[key].has_value?("Medium Severity")
  @low<< @scandata[key].values if @scandata[key].has_value?("Low Severity")
end

#skipping if no local checks is set
unless ARGV[2] == "nlc"
  @scaninfo.each do |key, value|
    if @scaninfo[key][:plugin_id] == "21745"
      @flc<< @scaninfo[key].values
      @flccount<< @scaninfo[key][:ip]
    end
    @ipcount<< @scaninfo[key][:ip]
  end

  #Comment out this section if you want failed local checks but not local admin info.
  @ladminh = @scaninfo.clone
  @ladminh.keep_if{|key| @ladminh[key][:plugin_id] == "10902"}
  #comment out this loop if you want to see all the local admins, or edit this code and the admins.txt file to match your enviorment.
  @ladminh.each do |key, value|
    @temp = @ladminh[key][:plugin_output].to_s
    @temp.sub!("\nThe following users are members of the 'Administrators' group :\n\n", "")
    @temp.sub!(/-\sRJO\\[Dd]omain\s[Aa]dmins\s\(Group\)/, "")
    @temp.sub!("- RJO\\PowerUsers (Group)\n", "")
    @temp.sub!(/-\s.*\\[Aa]dministrator\s\(User\)\n/, "")
    @temp.sub!(/-\sRJO\\London\sPower\sUsers\s\(Group\)/, "")
    if File.exists?('admins.txt')
      File.readlines('admins.txt').each do |line|
        @temp.sub!("-\sRJO\\#{line.chomp}\s\(User\)", "")
      end
    else
      puts "admins.txt wasn't found skipping that."
    end
    @temp.strip!
  end
  @ladminh.each do |key, value|
    unless @ladminh[key][:plugin_output].empty?
      @ladmin<< @ladminh[key].values 
      @ladmincount<< @ladminh[key][:ip]
    end
  end
else
  puts "skipping local checks and admins"
end
#Setting up the spreadsheet for the data
book = Spreadsheet::Workbook.new
format = Spreadsheet::Format.new :color => :black, :weight => :normal, :size => 12, :align => :left, :border => :thin
title_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 12, :align => :center, :border => :thin, :pattern => 1, :pattern_fg_color => :aqua
stat_title_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 20, :align => :center, :pattern => 1, :pattern_fg_color => :aqua
stat_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 12, :align => :left
#Stats workbook
sheet0 = book.create_worksheet
sheet0.name = 'Stats'
sheet0.row(0).push "Statisics of Scan"
sheet0.row(0).default_format = stat_title_format
sheet0.default_format=stat_format
sheet0.column(0).width = 70
sheet0.column(1).width = 30
sheet0.row(1).push 'Total IPs with at least one Crit or High finding.', "#{@critcount.uniq.count}"
sheet0.row(2).push 'Total IPs scanned that responded with an open port.', "#{@ipcount.uniq.count}"
unless ARGV[2] == "nlc"
sheet0.row(3).push 'Number of failed local checks.', "#{@flccount.uniq.count}"
sheet0.row(4).push 'Number of computers with non-standard local admins.', "#{@ladmincount.uniq.count}"
end

#Data workbooks
for i in 1..6 do
 i = book.create_worksheet
 i.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'Plugin ID', 'Plugin Output', 'Resolved', 'Comments'
 i.row(0).default_format = title_format
 i.default_format=format
 [0,2,3,8,9].each{|col| i.column(col).width = 20}
 [1,4,5,6,10,11,12].each{|col| i.column(col).width = 30}
end
sheet1 = book.worksheet 1
sheet1.name = 'Critical'
sheet2 = book.worksheet 2
sheet2.name = 'High'
sheet3 = book.worksheet 3
sheet3.name = 'Medium'
sheet4 = book.worksheet 4
sheet4.name = 'Low'
sheet5 = book.worksheet 5
unless ARGV[2] == "nlc"
  sheet5.name = 'Local Checks Failed'
  sheet6 = book.worksheet 6
  sheet6.name = 'Local Admins'
end


#Pushing the data into the spreadsheet and writing it.
row_num = 1
@critical.each do |row|
  sheet1.row(row_num).replace row
  row_num +=1
end
row_num = 1
@high.each do |row|
  sheet2.row(row_num).replace row
  row_num +=1
end
row_num = 1
@medium.each do |row|
  sheet3.row(row_num).replace row
  row_num +=1
end
row_num = 1
@low.each do |row|
  sheet4.row(row_num).replace row
  row_num +=1
end
row_num = 1
unless ARGV[2] == "nlc"
  @flc.each do |row|
    sheet5.row(row_num).replace row
    row_num +=1
  end
  row_num = 1
  #comment out this if you commened out the local admin part above. Or define @ladmin as an empty arry at the start of the script to avoid the error.
  @ladmin.each do |row|
    sheet6.row(row_num).replace row
    row_num +=1
  end
end

book.write ARGV[1]