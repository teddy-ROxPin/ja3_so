# ja3_so
Search [Zeek](https://zeek.org/) "ssl.log" file(s) created by [Security Onion](https://securityonionsolutions.com/) for known ja3 and ja3s values.
* Requires pandas.
```
pip3 install pandas
```
* ja3s results haven't been tested as I do not have a dataset for validation.

### Usage
* Can be fed a file or directory. 
	* If directory, a recursive search will be performed for all files named 'ssl.log' and results will be aggregated.
```
usage: ja3_so.py [-h] (-f FILE | -d DIRECTORY) [-c CUSTOM] [--ja3] [--ja3s] [--csv]

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to Zeek 'ssl.log' file created by Security Onion
  -d DIRECTORY, --directory DIRECTORY
                        path of directory to recursively search for Zeek 'ssl.log' files created by Security Onion
  -c CUSTOM, --custom CUSTOM
                        path to file containing custom ja3 values and descriptions. format is ja3:description one per line
  --ja3                 search for ja3 values (implied unless --ja3s is used)
  --ja3s                search for ja3s values
  --csv                 csv output
 ```
 
#### Output can be csv formatted:
```
python3 ja3_so.py -d /nsm/import/ --csv > results.csv
```
 
#### Custom ja3 values can be used:
```
python3 ja3_so.py -d /nsm/import/ -c custom-ja3-file-example.txt
```
*  See 'custom-ja3-file-example.txt' contents for format.
 
### Default ja3 values to search for:
4d7a28d6f2263ed61de88ca66eb011e3:emotet or iced  
6734f37431670b3ab4292b8f60f29984:trickbot  
72a589da586844d7f0818ce684948eea:metasploit or cobalt strike  
a0e9f5d64349fb13191bc781f81f42e1:metasploit or cobalt strike  
db42e3017c8b6d160751ef3a04f695e7:empire  
e7d705a3286e19ea42f587b344ee6865:tor  
 
### Default ja3s values to search for:
623de93db17d313345d7ea481e7443cf:trickbot  
70999de61602be74d4b25185843bd18e:metasploit  
80b3a14bccc8598a1f3bbe83e71f735f:emotet  
80b3a14bccc8598a1f3bbe83e71f735f:iced  
a95ca7eab4d47d051a5cd4fb7b6005dc:tor  
b742b407517bac9536a77a7b0fee28e9:cobalt strike  
e35df3e00ca4ef31d2b34bebaa2f862:empire  
 
### ja3 and ja3s sources:
https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967  
https://github.com/ByteSecLabs/ja3-ja3s-combo/blob/master/master-list.txt  
https://thedfirreport.com/