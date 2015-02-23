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
$output_critical = []
$output_high = []
$output_medium = []
$output_low = []

Nessus::Parse.new(ARGV[0]) do |scan|
scan.each_host do |host|
host.each_event do |event|
  unless event.name.include? "Compliance"
    if event.severity.critical?
      $output_critical.push ["#{host.ip}", "#{host.hostname}", "#{event.severity.in_words}", "#{event.port}", "#{event.name}", "#{event.synopsis}", "#{event.description}", "#{event.solution}", "#{event.cve}", "#{event.see_also}", "#{event.plugin_output}"] 
    elsif event.severity.high?
      $output_high.push ["#{host.ip}", "#{host.hostname}", "#{event.severity.in_words}", "#{event.port}", "#{event.name}", "#{event.synopsis}", "#{event.description}", "#{event.solution}", "#{event.cve}", "#{event.see_also}", "#{event.plugin_output}"]
    elsif event.severity.medium?
      $output_medium.push ["#{host.ip}", "#{host.hostname}", "#{event.severity.in_words}", "#{event.port}", "#{event.name}", "#{event.synopsis}", "#{event.description}", "#{event.solution}", "#{event.cve}", "#{event.see_also}", "#{event.plugin_output}"]
    elsif event.severity.low?
      $output_low.push ["#{host.ip}", "#{host.hostname}", "#{event.severity.in_words}", "#{event.port}", "#{event.name}", "#{event.synopsis}", "#{event.description}", "#{event.solution}", "#{event.cve}", "#{event.see_also}", "#{event.plugin_output}"]
     end 

  end
end
end 
end

#Setting up the spreadsheet for the data
book = Spreadsheet::Workbook.new
sheet1 = book.create_worksheet
sheet1.name = 'Critical'
sheet2 = book.create_worksheet
sheet2.name = 'High'
sheet3 = book.create_worksheet
sheet3.name = 'Medium'
sheet4 = book.create_worksheet
sheet4.name = 'Low'
sheet1.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'See Also', 'Plugin Output', 'Resolved', 'Comments'
sheet2.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'See Also', 'Plugin Output', 'Resolved', 'Comments'
sheet3.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'See Also', 'Plugin Output', 'Resolved', 'Comments'
sheet4.row(0).push 'IP', 'Host', 'Severity', 'Port', 'Plugin Name', 'Synopsis', 'Description', 'Solution', 'CVE', 'See Also', 'Plugin Output', 'Resolved', 'Comments'
format = Spreadsheet::Format.new :color => :black, :weight => :normal, :size => 12, :align => :left, :border => :thin 
title_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 12, :align => :center, :border => :thin, :pattern => 1, :pattern_fg_color => :aqua
sheet1.row(0).default_format = title_format
sheet1.default_format=format
sheet2.row(0).default_format = title_format
sheet2.default_format=format
sheet3.row(0).default_format = title_format
sheet3.default_format=format
sheet4.row(0).default_format = title_format
sheet4.default_format=format
[0,2,3,8].each{|col| sheet1.column(col).width = 20}
[1,4,5,6,9,10,11,12].each{|col| sheet1.column(col).width = 30}
[0,2,3,8].each{|col| sheet2.column(col).width = 20}
[1,4,5,6,9,10,11,12].each{|col| sheet2.column(col).width = 30}
[0,2,3,8].each{|col| sheet3.column(col).width = 20}
[1,4,5,6,9,10,11,12].each{|col| sheet3.column(col).width = 30}
[0,2,3,8].each{|col| sheet4.column(col).width = 20}
[1,4,5,6,9,10,11,12].each{|col| sheet4.column(col).width = 30}

#Pushing the data into the spreadsheet and writing it.
row_num = 1
$output_critical.each do |row|
  sheet1.row(row_num).replace row
  row_num +=1
end
row_num = 1
$output_high.each do |row|
  sheet2.row(row_num).replace row
  row_num +=1
end
row_num = 1
$output_medium.each do |row|
  sheet3.row(row_num).replace row
  row_num +=1
end
row_num = 1
$output_low.each do |row|
  sheet4.row(row_num).replace row
  row_num +=1
end
book.write ARGV[1]