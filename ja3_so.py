import argparse
import glob
import json
import os
import pandas as pd
import re
import sys

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-f", "--file", help="path to Zeek 'ssl.log' file created by Security Onion", type=str)
group.add_argument("-d", "--directory", help="path of directory to recursively search for Zeek 'ssl.log' files created by Security Onion", type=str)
parser.add_argument("-c","--custom",help="path to file containing custom ja3 values and descriptions. format is  ja3:description  one per line ", type=str)
parser.add_argument("--ja3", help="search for ja3 values (implied unless --ja3s is used)", action="store_true")
parser.add_argument("--ja3s", help="search for ja3s values", action="store_true")
parser.add_argument("--csv", help="csv output", action="store_true")
args = parser.parse_args()

# do not truncate panda rows
pd.set_option('display.max_rows', None)

# check for ja3 hits and print results
def ja3_results(ssl_df, filename, csv_out = 0):
    filter_ja3 = ssl_df['ja3'].notna()
    ja3_df = ssl_df[filter_ja3]
    filter_ja3_hits = ja3_df['ja3'].isin(family_ja3)
    unique_ja3_hits = (ja3_df[filter_ja3_hits].ja3.unique()).tolist()
    if len(ja3_df[filter_ja3_hits]):
        if not csv_out:
            print("\n{0}ja3 hits{0}".format("*" * 20))
            print(ja3_df[filter_ja3_hits].fillna('---none---').groupby(['id.orig_h', 'id.resp_h', 'server_name', 'ja3'], dropna=False).size().sort_values(ascending=False))
            print("filename: {0}".format(filename))
            for hit in unique_ja3_hits:
                print("{0} is assocated with {1}".format(hit, family_ja3[hit]))      
            print("{0}".format("*" * 48))
        if csv_out:
            csv_df = ja3_df[filter_ja3_hits].fillna('---none---').groupby(['id.orig_h', 'id.resp_h', 'server_name', 'ja3'], dropna=False).size().sort_values(ascending=False)
            print('src_ip,dest_ip,hostname,ja3,count')
            print(csv_df.to_csv(header=False))

    else:
        print("\nNo ja3 hits for: {0}".format(filename))

# check for ja3s hits and print results
def ja3s_results(ssl_df, filename):
    filter_ja3s = ssl_df['ja3s'].notna()
    ja3s_df = ssl_df[filter_ja3s]
    filter_ja3s_hits = ja3s_df['ja3s'].isin(family_ja3s)
    if len(ja3s_df[filter_ja3s_hits]):
        print("\n{0}ja3s hits{0}".format("*" * 20))
        print(ja3s_df[filter_ja3s_hits].groupby(['id.orig_h', 'id.resp_h', 'server_name', 'ja3s']).size().sort_values(ascending=False))
        print("{0}".format("*" * 49))
    else:
        print("\nNo ja3s hits for: {0}".format(filename))

def use_dict_file(file_path):
    family_ja3.clear()
    with open(file_path) as f:
        for line in f:
            (key, val) = line.split(":")
            family_ja3[key] = val.strip("\n")

# known ja3, ja3s, and their corresponding c2 family
family_ja3 = {"6734f37431670b3ab4292b8f60f29984": "trickbot", "4d7a28d6f2263ed61de88ca66eb011e3": "emotet or iced", "e7d705a3286e19ea42f587b344ee6865": "tor",
                "72a589da586844d7f0818ce684948eea": "metasploit or cobalt strike", "a0e9f5d64349fb13191bc781f81f42e1": "metasploit or cobalt strike",
                "db42e3017c8b6d160751ef3a04f695e7": "empire"}
family_ja3s = {"623de93db17d313345d7ea481e7443cf": "trickbot", "80b3a14bccc8598a1f3bbe83e71f735f": "emotet", "80b3a14bccc8598a1f3bbe83e71f735f": "iced", 
                "a95ca7eab4d47d051a5cd4fb7b6005dc": "tor", "70999de61602be74d4b25185843bd18e": "metasploit", "b742b407517bac9536a77a7b0fee28e9": "cobalt strike", 
                "e35df3e00ca4ef31d2b34bebaa2f862": "empire"}

# to be used for args flags
get_ja3 = 0
get_ja3s = 0
csv_out = 0

# set variables depending on ja3/ja3s flags
if (args.ja3) or (not args.ja3 and not args.ja3s):
    get_ja3 = 1
if args.ja3s:
    get_ja3s = 1
if (args.csv) and (not args.ja3s):
    csv_out = 1
if (args.csv and args.ja3s):
    print("CSV output not setup for ja3s yet.")
    exit()
if args.custom:
    use_dict_file(args.custom)

# if file provided
if args.file:
    try:
        ssl_df = pd.read_json(args.file, lines=True)
    except:
        print("Unable to find or open file (or not json file): {0}".format(args.file))
        exit(1)
    else:
        # search file for ja3 and/or ja3s hits
        if get_ja3:
            ja3_results(ssl_df, args.file, csv_out)
        if get_ja3s:
            ja3s_results(ssl_df, args.file)
#if directory provided, combine files into one output
elif args.directory:
    # add trailing / to directory path if needed
    if re.match('.*/$', args.directory) is None:
        dir_to_recurse = args.directory + '/'
    else:
        dir_to_recurse = args.directory
    # recurse directory and add ssl.log files to list    
    files = [f for f in glob.glob(dir_to_recurse + '**/ssl.log', recursive=True)]

    ssl_df = pd.DataFrame()

    # search each file for ja3 and/or ja3s hits
    for afile in files:
        try:
            ssl_df_curr = pd.read_json(afile, lines=True)
        except:
            print("Unable to find or open file (or not json file): {0}".format(afile))
        else:
            ssl_df = ssl_df.append(ssl_df_curr)

    if get_ja3:
        ja3_results(ssl_df, 'combined files', csv_out)
    if get_ja3s:
        ja3s_results(ssl_df, 'combined files')