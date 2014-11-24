#!/usr/bin/env ruby

require 'rubygems'
require 'nessus'
require 'spreadsheet'

#Usage and help.
unless ARGV[0] and ARGV[1]
  puts "Usage nessus_compliance.rb name.nessus output.xls (must be xls not xlsx)"
  puts "This script takes a .nessus file which compliance infomration such as CIS audit files and splits out only the cpliance findings and puts the failed, error, and warning issues each in it's own tab in a spreadsheet and ditches the passed ones."
  exit 1
end

#Opening the .nessus file and pushing the compliance failed, error, and warning issues into arrays, ditching passed because no one cares.
$outputf = []
$outpute = []
$outputw = []
Nessus::Parse.new(ARGV[0]) do |scan|
scan.each_host do |host|
host.each_event do |event|
  if event.name.include? "Compliance"
    if event.description.include? "[FAILED]"
      $outputf.push ["#{host.hostname}", "#{event.severity.in_words}", "#{event.description}"] 
    elsif event.description.include? "[ERROR]"
      $outpute.push ["#{host.hostname}", "#{event.severity.in_words}", "#{event.description}"] 
    elsif event.description.include? "[WARNING]"
      $outputw.push ["#{host.hostname}", "#{event.severity.in_words}", "#{event.description}"] 
    end 

  end
end
end 
end

#Setting up the spreadsheet for the data
book = Spreadsheet::Workbook.new
sheet1 = book.create_worksheet
sheet1.name = 'FAILED'
sheet2 = book.create_worksheet
sheet2.name = 'ERROR'
sheet3 = book.create_worksheet
sheet3.name = 'WARNING'
sheet1.row(0).push 'Host', 'Severity', 'Description', 'Resolved', 'Comments'
sheet2.row(0).push 'Host', 'Severity', 'Description', 'Resolved', 'Comments'
sheet3.row(0).push 'Host', 'Severity', 'Description', 'Resolved', 'Comments'
format = Spreadsheet::Format.new :color => :black, :weight => :normal, :size => 12, :align => :left, :border => :thin 
title_format = Spreadsheet::Format.new :color => :black, :weight => :bold, :size => 12, :align => :center, :border => :thin, :pattern => 1, :pattern_fg_color => :aqua
sheet1.row(0).default_format = title_format
sheet1.default_format=format
sheet2.row(0).default_format = title_format
sheet2.default_format=format
sheet3.row(0).default_format = title_format
sheet3.default_format=format
[0,1,3,4].each{|col| sheet1.column(col).width = 20}
[2].each{|col| sheet1.column(col).width = 50}
[0,1,3,4].each{|col| sheet2.column(col).width = 20}
[2].each{|col| sheet2.column(col).width = 50}
[0,1,3,4].each{|col| sheet3.column(col).width = 20}
[2].each{|col| sheet3.column(col).width = 50}

#Pushing the data into the spreadsheet and writing it.
row_num = 1
$outputf.each do |row|
  sheet1.row(row_num).replace row
  row_num +=1
end
row_num = 1
$outpute.each do |row|
  sheet2.row(row_num).replace row
  row_num +=1
end
row_num = 1
$outputw.each do |row|
  sheet3.row(row_num).replace row
  row_num +=1
end
book.write ARGV[1]