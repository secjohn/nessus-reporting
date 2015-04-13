#!/usr/bin/env ruby

require 'rubygems'
require 'nessus'
require 'spreadsheet'

#Usage and help.
unless ARGV[0] and ARGV[1]
  puts "Usage nessus_vuln.rb name.nessus output.xls (must be xls not xlsx)"
  puts "This script takes a .nessus file and edits out any compliance findings and ones with no risk and splits the others out in tabs sorted by host."
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

@scandata.each do |key, value|
  @critical<< @scandata[key].values if @scandata[key].has_value?("Critical Severity")
  @high<< @scandata[key].values if @scandata[key].has_value?("High Severity")
  @medium<< @scandata[key].values if @scandata[key].has_value?("Medium Severity")
  @low<< @scandata[key].values if @scandata[key].has_value?("Low Severity")
end

@scaninfo.each do |key, value|
  @flc<< @scaninfo[key].values if @scaninfo[key][:plugin_id] == "21745"
end

@ladminh = @scaninfo.keep_if{|key| @scaninfo[key][:plugin_id] == "10902"}
@ladminh.each do |key, value|
  temp = @ladminh[key][:plugin_output].to_s
  temp.sub!("\nThe following users are members of the 'Administrators' group :\n\n", "")
  temp.sub!(/-\sRJO\\[Dd]omain\s[Aa]dmins\s\(Group\)/, "")
  temp.sub!("- RJO\\PowerUsers (Group)\n", "")
  temp.sub!(/-\s.*\\Administrator\s\(User\)\n/, "")
  temp.strip!
end
@ladminh.each do |key, value|
  @ladmin<< @ladminh[key].values unless @ladminh[key][:plugin_output].empty?
end

#Setting up the spreadsheet for the data
book = Spreadsheet::Workbook.new
format = Spreadsheet::Format.new :color => :black, :weight => :normal, :size => 12, :align => :left, :border => :thin
title_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 12, :align => :center, :border => :thin, :pattern => 1, :pattern_fg_color => :aqua
for i in 0..5 do
 i = book.create_worksheet
 i.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'Plugin ID', 'Plugin Output', 'Resolved', 'Comments'
 i.row(0).default_format = title_format
 i.default_format=format
 [0,2,3,8,9].each{|col| i.column(col).width = 20}
 [1,4,5,6,10,11,12].each{|col| i.column(col).width = 30}
end
sheet1 = book.worksheet 0
sheet1.name = 'Critical'
sheet2 = book.worksheet 1
sheet2.name = 'High'
sheet3 = book.worksheet 2
sheet3.name = 'Medium'
sheet4 = book.worksheet 3
sheet4.name = 'Low'
sheet5 = book.worksheet 4
sheet5.name = 'Local Checks Failed'
sheet6 = book.worksheet 5
sheet6.name = 'Local Admins'



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
@flc.each do |row|
  sheet5.row(row_num).replace row
  row_num +=1
end
row_num = 1
@ladmin.each do |row|
  sheet6.row(row_num).replace row
  row_num +=1
end

book.write ARGV[1]