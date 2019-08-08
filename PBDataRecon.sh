#/!bin/bash
# License: GPL-3.0-or-later

while :
do

# Write the metadata for the last 100 pastes in to a JSON file
 curl -s https://scrape.pastebin.com/api_scraping.php?limit=100 > paste250.json


#Write the keyval values to a file called keyvals.txt
curl -s https://scrape.pastebin.com/api_scraping.php?limit=100 | grep key | grep -v '"0"' | awk '{print $2}' | sed 's/"//g' | sed 's/,//g'  > keyvals.txt                                                                                                  
 

#Launches Python Rules and Data Engine
python ./PBDataRecon.py

#sleeps for 1 minute
sleep 2m


done


