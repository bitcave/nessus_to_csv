#!/usr/bin/env ruby

require 'rubygems'
require 'ruby-nessus'
require 'csv'

if ARGV.empty?
	abort("Usage: ruby nessus_to_csv.rb [PATH TO NESSUS FILE] \nThis will generate two CSV files in the current directory -> \"detailed_findings\" and \"summary_of_findings\"")	  
else
	nessus_output_file = ARGV[0]
end

nessus_CSV_detailed = "detailed_findings"
nessus_CSV_summary = "summary_of_findings"

# Detailed CSV File
CSV.open(nessus_CSV_detailed, "wb") do |csv|
	
	# Header Row
	csv << ["host_ip", "host_name", "host_os", "port", "vulnerability_severity", "vulnerability_name", "vulnerability_synopsis", "vulnerability_description", "vulnerability_solution", "vulnerability_info", "vulnerability_risk", "vulnerability_cve"] 

	# Data Rows	
	Nessus::Parse.new(nessus_output_file) do |scan|
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
CSV.open(nessus_CSV_summary, "wb") do |csv|
	
	# Header Row
	csv << ["host_ip", "host_name", "no_of_high", "no_of_meduim", "no_of_low", "no_of_info"] 

	# Data Rows	
	Nessus::Parse.new(nessus_output_file) do |scan|
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
  
