# PBDataRecon
# Version 1.0 8/6/2019
# License: GPL-3.0-or-later

import pymysql
import json
import requests
import time
import string
import re
import base64


# --- Set the parameters below to determine what gets parsed and stored in the database --- #
# --- More granular changes can be made below in the conditional statements by modifying ---#
# --- the PasteContent = "yes" variable                                                  ---#


# Add a string you are interested in
# I.e.: UserString = "Defcon Recon"
UserString = "Your Input Here"


# Add your company's domain
# I.e.: UserDomain = "Defcon.org"
UserDomain = "Your Input Here"

# Add a name you are interested in
# I.e.: UserDefName = "Dark Tangent"
UserDefName = "Your Input Here"

# Add a RegEx
# I.e.: UserRegEx = '^D[a-z]{6}'
UserRegEx = "Your Input Here"


# Find and save Pastes before they expire (Disappear) (yes/no)
SaveExpiringPastes = "yes"

# Parse and store information on accounts (yes/no)
CheckForAccounts = "yes"

# Parse and store information on possible and confirmed hashes and keys (yes/no)
CheckForHashes = "yes"

# Parse and store information on possible tools and exploits (yes/no)
CheckForExploits = "yes"

# Parse and store on posted tor sites (yes/no)
CheckForTorSites = "yes"

# Parse and store information on posted about Anonomous' activities  (yes/no)
CheckForAnon = "yes"

# Do not save large pastes
# KeepSmall should = "yes" to if you want to reduce DB size
KeepSmall = "no"


# Verbose Mode: off/medium/high/ultra
# Suggest ultra for debugging new code
# Suggest high for tuning and refining
VerboseMode = "ultra"


#Creds and Housekeeping
json_file = 'paste250.json'
mysql_db = 'PBDataRecon'
db_user = '<Your User Name Here>'
CheckForChesters = "yes"
db_password = '<Your Password Here>'
key_file = 'keyvals.txt'
pasteType = "Unknown"


# read JSON file which is in the next parent folder
json_data = open(json_file).read()
json_obj = json.loads(json_data)

# connect to MySQL
con = pymysql.connect(host='localhost', user=db_user, passwd=db_password, db=mysql_db, charset='utf8mb4')
cursor = con.cursor()



#####       Extracts and saves Metadata        #####

# parse json data to SQL insert
insertKeyList = []

for i, item in enumerate(json_obj):
    keyval = item.get("key", None)
    date = item.get("date", None)
    expire = item.get("expire", None)
    size = int(item.get("size", None))
    title = item.get("title", None)
    syntax = item.get("syntax", None)
    user = item.get("user", None)
    
    #Calculates how long the expiration is
    if int(expire) == 0:
        pasteTime = 999999 # 999999 = never expires
    else:    
        pasteTime = int(expire) - int(date)
        insertKeyList.append(keyval)
        pasteType = "Expires"
        
       
        
        if (SaveExpiringPastes == "yes" and pasteType == "Expires"):
            r = requests.get('https://scrape.pastebin.com/api_scrape_item.php?i='+keyval)
            cursor.execute(
                "INSERT INTO PasteContent (keyval,paste,pasteType)  VALUES (%s, %s, %s)",
                (keyval, r.text.encode('utf-8'), pasteType))
            con.commit()
            
            if (VerboseMode == "medium"):
                print pasteType
            
            elif (VerboseMode == "ultra"):
                OutputData = r.text.encode('utf8', 'replace')
                print "Keyval: ", keyval, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]


# Determines if file is large for the KeepSmall condition
# This can be changed to any int value
if size > 474835:
    BigPaste = "yes"
else:
    BigPaste = "no"

if (VerboseMode == "ultra"):
    print "BigPaste set equal to: ", BigPaste 
        
        
# Inserts meta data
cursor.execute(
    "INSERT INTO MetaDataValues (keyval, date, expire, size, title, syntax, user, pasteTime)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
    (keyval, date, expire, size, title, syntax, user, pasteTime))
con.commit()



#####   Analyzes and inserts past contents     #####


with open(key_file, 'r+') as key_file:
    for line in key_file:
        
        # remove trailing newline
        line = line.rstrip()
        
        #For pastes who's metadata says they expire
        if (line in insertKeyList):
            PasteContent = "yes"
            
        else:
            PasteContent = "no"

        # Insert in to pastecontent table        
        r = requests.get('https://scrape.pastebin.com/api_scrape_item.php?i='+line)
        data = r.text
            
# User Defined Search Terms
        
        # Your String
        if ('Your Input Here' not in UserString):
            if (UserString in data.lower()):
                    PasteContent = "yes"
                    pasteType = UserString

        # Your Domain
        if ('Your Input Here' not in UserDomain):
            if (UserDomain in data.lower()):
                    PasteContent = "yes"
                    pasteType = UserDomain

 
        # Your Search Name
        if ('UserRegEx' not in UserDefName):
            if (UserDefName in data.lower()):
                    PasteContent = "yes"
                    pasteType = UserDefName

        # Your RegEx
        if ('Here' not in UserRegEx):
            try:
                if (re.match(UserRegEx, data)):
                    PasteContent = "yes"
                    pasteType = UserRegEx
                        
            except:
                print "Please check your RegEx for formatting issues: ", UserRegEx
                
              
         
  # Hashes
        if (CheckForHashes == "yes"):
  
            # Reg Ex's used
            MD5pattern = '^[a-f0-9]{32}$'
            SHA256pattern = '^[a-f0-9]{64}$'
            SHA512pattern = '^[a-f0-9]{128}$'
            openVPN32bit = '^[a-f0-9]{32}$'
            Base64pattern = '^[a-ZA-Z]$'
            Hashpattern1 = '^![a-zA-Z0-9\(\)]{300,}'
            Hashpattern2 = '^S3[a-zA-Z0-9\(\)]{300,}'
            Hashpattern3 = '^\+c[a-zA-Z0-9\(\)]{300,}'
            JSFuckPattern = '[^a-zA-Z0-9]'
      
      
            # Check for MD5
            if (re.match(MD5pattern, data) and not 'http' in data.lower()):
                PotentialHash = "High"
                PasteContent = "yes"
                pasteType = "MD5"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
               
    
            # Check for SHA256
            elif (re.match(SHA256pattern, data) and not 'http' in data.lower()):
                PotentialHash = "High"
                PasteContent = "yes"
                pasteType = "SHA256"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
        
                
            # Check for SHA256
            elif (re.match(SHA512pattern, data) and not('\n' in data) and not 'minecraft' in data.lower()):
                PotentialHash = "High"
                PasteContent = "yes"
                pasteType = "SHA512"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
               
            # Check for AES256
            elif (not(' ' in data) and not('.' in data) and not('\n' in data) and (data.endswith("=")) and (len(data)==24) and not 'http' in data.lower()):
                PotentialHash = "Very High"
                PasteContent = "yes"
                pasteType = "AES256"

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
      
            elif (not(' ' in data) and (len(data)==24) and not('\n' in data) and not('.' in data) and not 'http' in data.lower()):
                PotentialHash = "High"
                PasteContent = "yes"
                pasteType = "AES256"

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
                   
                
            # Possible Hash Type 1    
            elif (re.match(Hashpattern1, data) and not('\n' in data)):
                PotentialHash = "Certain"
                PasteContent = "yes"
                pasteType = "Possible Hash"                        
          
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
              
          
            # Possible Hash Type 2    
            elif (re.match(Hashpattern2, data) and not('\n' in data) and not(' ' in data)):
                PotentialHash = "Certain"
                PasteContent = "yes"
                pasteType = "Possible Hash"                  
            
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                           
            # Possible Hash Type 2 (alternate)
            elif(re.match("!", data) and not('\n' in data) and not(' ' in data)):
                PotentialHash = "Certain"
                PasteContent = "yes"
                pasteType = "Possible Hash"
                

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
                
            # Possible Hash Type 3    
            elif (re.match(Hashpattern3, data) and not('\n' in data)):
                PotentialHash = "Certain"
                PasteContent = "yes"
                pasteType = "Possible Hash"

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
               
            # Possible Hash Type 4 
            elif ((not(' ' in data) and not('\n' in data)) and (len(data) > 65) and '/' in data and not 'http' in data.lower()):
                PotentialHash = "High"
                PasteContent = "yes"
                pasteType = "Possible Hash" 

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                      
                 
            # Possible Hash Type 5
            elif ((not(' ' in data) and not('\n' in data)) and (len(data) > 65) and not 'http' in data.lower() and not '$' in data.lower()):
                PotentialHash = "Medium"
                PasteContent = "yes"
                pasteType = "Possible Hash"

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
                
            # Possible Key
            elif ((not(' ' in data) and not('\n' in data)) and (len(data) > 8) and not 'http' in data.lower() and '-' in data ):
                PotentialHash = "Medium"
                PasteContent = "yes"
                pasteType = "Possible Key"              
               
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                
            
                                     
            # Accounts
            if (CheckForAccounts == "yes"):
                
                # Check if DOX 
                if ((' dox ' in data.lower() or 'doxing' in data.lower() )and 'address' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "DOX"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                
                
                
                # Generic Dump   
                elif ('password' in data.lower() and 'dump' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "Password Dump"
                 
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                 
                
               
                # Consistent with password dumps
                elif (':' in data and ('gmail.com' in data.lower() or 'hotmail.com' in data.lower() or 'mail.ru' in data.lower())):
                    PasteContent = "yes" 
                    pasteType = "Account.Email" 
                
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                
                
          
                # Check for SQLMap Dump
                elif (('--+--' in data) and ('dump' in data.lower() or 'passwords' in data.lower() or 'sqlmap' in data.lower())):
                    PasteContent = "yes"
                    pasteType = "Password Dump"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
  
        

    # Tools, XSS, exploits and cool code
            if (CheckForExploits == "yes"):
                
                # Hiding in HTML- Often XSS
                if ('fromcharcode' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "XSS Code0"
                    
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    
                    
                elif ('innerhtml' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "XSS Code"                    
                    
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    
                    
                # Detects some Type 0 XSS filter bypass contributed by Jerry Decime https://jdecime.com
                elif ('script#' in data.lower() or 'iframe#' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "XSS Code"
                    
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    
                    
                # Detects some WAF-evading XSS contributed by Hanson Nottingham
                elif ('3cscript' in data.lower() or '1dhttp' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "XSS Code"
                    
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    
                    
                # Often consistent with the ASCII art from a Linux toolz
                elif (('\(_\)' in data.lower() and not 'minecraft' in data.lower()) and (not 'bit.do' in data or not 'my.su' in data)):
                    PasteContent = "yes"
                    pasteType = "Toolz"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]        
        
                # Consistent with exploit code
                elif ('ddos' in data.lower() or 'exploit' in data.lower() or 'metasploit' in data.lower() or ' dos ' in data.lower() and not 'minecraft' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "Toolz"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]        
        
                # Checks for API keys 
                elif (('curl' in data.lower() or 'wget' in data.lower()) and ('api.' in data.lower())):
                    PasteContent = "yes"
                    pasteType = "API Key"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    
                    
                # Checks for API keys II
                elif (' api ' in data.lower() and 'keys' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "API Key"                    

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]

                # Checks for JSFuck
                elif (not(' ' in data) and re.match(JSFuckPattern, data) and '!' in data and '+' in data):
                    PasteContent = "yes"
                    pasteType = "JSFuck"

                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                            
                            
        # Check if Anon Op
        if (CheckForAnon == "yes"):
            if ((' #op' in data.lower()  and not 'optional' in data.lower())or 'hacked by anon' in data.lower()):
                PasteContent = "yes"
                pasteType = "Anon"

                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]

        # Check if Tor site
        if (CheckForTorSites == "yes"):
            if ('.onion' in data.lower()):
                PasteContent = "yes"
                pasteType = "Tor"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]

        #Bust the Chesters
        # High rate of false positive findings.
        # Please report findings of child trasfficking or abuse to tips.fbi.gov
        
        if (CheckForChesters == "yes"):        
            if (('boy' in data.lower() or 'girl' in data.lower()) and ('loli' in data.lower() or 'lolita' in data.lower())):
                PasteContent = "yes"
                pasteType = "Chesters"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
    
            elif (' pedo' in data.lower()  and 'onion' in data.lower()):
                PasteContent = "yes"
                pasteType = "Chesters"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]

            elif (' pedo' in data.lower()  and ('onion' in data.lower() or 'twitter' in data.lower())):
                PasteContent = "yes"
                pasteType = "Chesters"
                
                if (VerboseMode == "ultra"):
                    OutputData = data.encode('utf8', 'replace')
                    print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]                    


                    
            # Anon's Child Safety Ops
            elif (CheckForChesters == "yes"):        
                if ('OpChildSafety' in data.lower()  or 'OpPedoHunt' in data.lower() or 'pedohunters' in data.lower()):
                    PasteContent = "yes"
                    pasteType = "Chesters"
                    
                    if (VerboseMode == "ultra"):
                        OutputData = data.encode('utf8', 'replace')
                        print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
                        
         
        #Nothing matches. The meta data is stored in the DB but not the contents of the paste 
        else:
            PasteContent = "no"
            pasteType = "No Matches"
 
            if (VerboseMode == "ultra"):
                OutputData = data.encode('utf8', 'replace')
                print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
  
          
        # Spammer's encoding screwing up data       
        if ('bit.do' in data or 'my.su' in data):
            PasteContent = "no"
            if (VerboseMode == "ultra"):
                print keyval, "| blocked encoded spammer!"
                donothingnow = "true"
       
       
        # Verbose Mode Output. Set variable at top of page
        if (VerboseMode == "medium" and PasteContent == "yes"):
            print pasteType
        elif (VerboseMode == "high"):
            OutputData = data.encode('utf8', 'replace')
            OutputData = OutputData.strip('\n')
            print "Keyval: ", line, " | pasteType: ", pasteType, " | Paste: ", OutputData[:20]
            
        if (KeepSmall == "yes" and BigPaste == "yes"):
            PasteContent = "no"
            
        #Inserts Contents of paste
        if (PasteContent == "yes"):
                cursor.execute(
                    "INSERT INTO PasteContent (keyval,Paste,pasteType)  VALUES (%s, %s, %s)",
                    (line, data, pasteType))
                con.commit()
                
con.close()
