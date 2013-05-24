#!/usr/bin/env python
import shutil

fail_file = 'out/parse_fail.txt'
results_dir = 'out/results/'
parse_dir = 'out/parse/'

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
    print "Unknown Error for "+str(run[0])
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

  for run in runs:
    error_type = identifyParseErrorType(run)
    if error_type == ERROR_NONE:
      continue
    if error_type == ERROR_FAILED_TO_PARSE_1:
    if error_type == ERROR_FAILED_TO_IDENTIFY_TEMPLATE:
    if error_type == ERROR_NO_TEMPLATE:
    if error_type == ERROR_UNKNOWN:
      continue # skip for now





