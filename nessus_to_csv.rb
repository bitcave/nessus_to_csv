# Script to parse Nessus output to csv file
# Author: Michael Gianarakis
# Date: 29 July 2011
# Version 0.1 (i.e. the hack version that is very poorly coded)

#!/usr/bin/env ruby
require 'rubygems'
require 'ruby-nessus'
require 'csv'

# Name of the Nessus output file
puts "Type the name of the Nessus output file:"
varNessusOutputFile = gets.chomp + '.nessus'

# Name of the detailed CSV file to output to
puts "Type the name of the detailed CSV file: "
varNessusCSVFile = gets.chomp

# Name of the summary CSV file to output to
puts "Type the name of the summary CSV file: "
varNessusCSVSumFile = gets.chomp

# Detailed CSV File
CSV.open(varNessusCSVFile, "wb") do |csv|
	
	# Header Row
	csv << ["host_ip", "host_name", "host_os", "port", "vulnerability_severity", "vulnerability_name", "vulnerability_synopsis", "vulnerability_description", "vulnerability_solution", "vulnerability_info", "vulnerability_risk", "vulnerability_cve"] 

	# Data Rows	
	Nessus::Parse.new(varNessusOutputFile) do |scan|
		scan.each_host do |host|
			host_ip = host.ip
			host_name = host.hostname
			host_os = host.os_name
		
			host.each_event do |event|
				vuln_name = event.name if event.name
				vuln_synopsis = event.synopsis.to_s.gsub(/[,"\n""""]/, ' ') if event.synopsis
				vuln_severity = event.severity.in_words
				vuln_info = event.data.to_s.gsub(/[,"\n""""]/, ' ') if event.data
				vuln_solution = event.solution.to_s.gsub(/[,"\n""""]/, ' ')
				vuln_port = event.port
				vuln_risk = event.risk
				vuln_description = event.description.to_s.gsub(/[,"\n""""]/, ' ')
				vuln_cve = event.cve
				csv << [host_ip, host_name, host_os, vuln_port, vuln_severity, vuln_name, vuln_synopsis, vuln_description, vuln_solution, vuln_info, vuln_risk, vuln_cve]
			end
		end
	end
end

# Summary CSV File
CSV.open(varNessusCSVSumFile, "wb") do |csv|
	
	# Header Row
	csv << ["host_ip", "host_name", "no_of_high", "no_of_meduim", "no_of_low", "no_of_info"] 

	# Data Rows	
	Nessus::Parse.new(varNessusOutputFile) do |scan|
		scan.each_host do |host|
			host_ip = host.ip
			host_name = host.hostname
			host_os = host.os_name
			no_of_high = host.high_severity_count
			no_of_medium = host.medium_severity_count
			no_of_low = host.low_severity_count
			no_of_info = host.informational_severity_count
			csv << [host_ip, host_name, host_os, no_of_high, no_of_medium, no_of_low, no_of_info]
		end
	end
end
  
