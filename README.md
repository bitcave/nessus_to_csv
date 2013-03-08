#nessus_to_csv

This is a simple script that I put together one afternoon for a non-technical colleague who wanted to include some results from Nessus into a report he was writing for an internal audit.

Needs the ruby-nessus gem:

`gem install ruby-nessus`

Using the script is simple:

`ruby nessus_to_csv.rb [PATH TO NESSUS FILE]`

It will output two CSV files "detailed_findings" and "summary_of_findings" to the current directory.

Also don't use this. Use [Prenus](https://github.com/AsteriskLabs/prenus) instead.