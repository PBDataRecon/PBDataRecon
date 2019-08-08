# PBDataRecon
Pastebin Analysis and Storage Tool



**Pastebin API**

Pastebin does not use an actual API key but instead whitelists IP addresses. There is no cost for a key, but only "LIFETME PRO" accounts can whitelist IP addresses. Go to [Pastebin's Scraping API page] (https://pastebin.com/doc_scraping_api) to set up your account and IP.


**Creating Database and Tables**
1.	Create a database named "PBDataRecon" or use a different name. Be sure if you use a different name to change the "mysql_db=" config in line 67 of the PBDataRecon.py file.
2.	Create the two necessary tables using the following scripts:
    - createMetaDataValuesTable.sql
    - createPasteContentTable.sql
3.	Upate lines 69 & 71 of the PBDataRecon.py file with your DB's credentials


**Files**

You will need to store PBDataRecon.py and PBDataRecon.sh in the same directory and make them executable (chmod 755 PBDataRecon.sh PBDataRecon.py).


**Start Collecting Data**

Simply execute the bash script PBDataRecon.sh. You can change how frequently the API collects pastes and how many pastes it collects by modifying this file.


**Troubleshooting**
1.	Warning about character encoding are typically a sign of your OS or database not being able to handle one of the many character sets found in pastebin. These errors are handled and will not stop PBDataRecon from collecting data.
2.	The most likely cause of the “ValueError: No JSON object could be decoded” error is that you either have no Internet connection or your current IP is not whitelisted. 

**Verbose Mode**
There are four levels or output: off/medium/high/ultra
   -Suggest ultra for debugging new code
   -Suggest high for tuning and refining

You set the level on line 63 in the "VerboseMode = " variable.

**Limiting large files**
Pastebin files can reach up to 16MB. Set the "KeepSmall = "yes" variable to prevent large filews from being saved.




