#!/usr/bin/env python
import shutil
import os

fail_file = 'out/parse_fail.txt'
results_dir = 'out/results/'
zip_folder = 'zip/'
whois_folder = 'zip/whois/'


if not os.path.exists(zip_folder):
  os.makedirs(zip_folder)
if not os.path.exists(whois_folder):
  os.makedirs(whois_folder)

#used as enums for error type
ERROR_NONE = 0
ERROR_UNKNOWN = 1
ERROR_FAILED_TO_PARSE_1 = 2
ERROR_FAILED_TO_IDENTIFY_TEMPLATE = 3
ERROR_NO_TEMPLATE = 4
ERROR_STACK = 5

def linesToRuns(lines):
  ret = list()
  last = None
  for line in lines:
    if len(line) > 1:
      if line[0:2] == "--":
        last[1].append(line[2:].strip())
      else:
        if last:
          ret.append(last)
        last = (line.strip(),list())
  if last:
    ret.append(last)
  return ret


def identifyParseErrorType(run):
  error_len = len(run[1])
  if error_len == 0:
    print "No error for: "+str(run)
    return ERROR_NONE
  if error_len == 1:
    error = run[1][0]
    if error == 'Failed to parse (#1)':
      return ERROR_FAILED_TO_PARSE_1
    if error == 'Failed to identify "whois" template : is this .biz/.com/.info/.net/.org ??':
      return ERROR_FAILED_TO_IDENTIFY_TEMPLATE
    if error[0:15] == 'No template for' and error[-32:] == 'at demos/parsewhois.pl line 109.':
      return ERROR_NO_TEMPLATE
    print "Unknown Error for "+str(run)
    print error
    return ERROR_UNKNOWN
  if error_len > 1:
    return ERROR_STACK



if __name__=="__main__":
  fh = open(fail_file)
  lines = fh.readlines()
  fh.close()

  print "parsing runs"
  runs = linesToRuns(lines)
  print "found " +str(len(runs))+" runs"

  counts = [0,0,0,0,0,0]


  #use a file for each error type
  file_error1 = open(zip_folder+"error1.txt",'w+')
  file_error1.write('Domains with Error: Failed to parse (#1)\n')
  file_error2 = open(zip_folder+"error2.txt",'w+')
  file_error2.write('Domains with Error: Failed to identify "whois" template : is this .biz/.com/.info/.net/.org ??\n')
  file_error3 = open(zip_folder+"error3.txt",'w+')
  file_error3.write('Domains with Error: No template for $DOMAIN at demos/parsewhois.pl line 109.\n')
  file_error4 = open(zip_folder+"error4.txt",'w+')
  file_error4.write('Domains that throw exceptions in the parse code\n')
  
  for run in runs:
    shutil.copy(results_dir+run[0],whois_folder+run[0])
    error_type = identifyParseErrorType(run)
    
    if error_type == ERROR_NONE:
      counts[ERROR_NONE]+=1
    
    elif error_type == ERROR_FAILED_TO_PARSE_1:
      counts[ERROR_FAILED_TO_PARSE_1]+=1
      file_error1.write(run[0]+"\n")
    
    elif error_type == ERROR_FAILED_TO_IDENTIFY_TEMPLATE:
      counts[ERROR_FAILED_TO_IDENTIFY_TEMPLATE]+=1
      file_error2.write(run[0]+"\n")
    
    elif error_type == ERROR_NO_TEMPLATE:
      counts[ERROR_NO_TEMPLATE]+=1
      file_error3.write(run[0]+"\n")
    
    elif error_type == ERROR_STACK:
      counts[ERROR_STACK]+=1
      file_error4.write(run[0]+"\n")
      for line in run[1]:
        file_error4.write(line+"\n")
      file_error4.write("\n")
    
    elif error_type == ERROR_UNKNOWN:
      counts[ERROR_UNKNOWN]+=1


  file_error1.close()
  file_error2.close()
  file_error3.close()
  file_error4.close()

  print "ERROR_NONE: "+str(counts[ERROR_NONE])
  print "ERROR_FAILED_TO_PARSE_1: "+str(counts[ERROR_FAILED_TO_PARSE_1])
  print "ERROR_FAILED_TO_IDENTIFY_TEMPLATE: "+str(counts[ERROR_FAILED_TO_IDENTIFY_TEMPLATE])
  print "ERROR_NO_TEMPLATE: "+str(counts[ERROR_NO_TEMPLATE])
  print "ERROR_STACK: "+str(counts[ERROR_STACK])
  print "ERROR_UNKNOWN: "+str(counts[ERROR_UNKNOWN])



