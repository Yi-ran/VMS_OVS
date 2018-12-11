#!/usr/bin/python

import os, sys
import subprocess

# argv[1] analysis directory

if len(sys.argv) == 1:
  print """
- argv[1] analysis directory
"""

cmd = "tshark -r %s -R \"tcp.analysis.ack_rtt\" \
    -e tcp.analysis.ack_rtt -T fields"

path = sys.argv[1]

for bench in os.listdir(path):
  sub_path = path + "/" + bench.strip()
  log = open("./" + bench.strip() + "-rtt-10g", "w")
  print "Entering" + sub_path

  for t in os.listdir(sub_path):
    sub_sub_path = sub_path + "/" + t
    log.write("====" + t + "\n")
    print "Entering" + sub_sub_path

    for f in os.listdir(sub_sub_path):
      print "Processing" + sub_sub_path + "/" + f
      proc = subprocess.Popen(cmd%(sub_sub_path + "/" + f), \
          shell=True, stdout=subprocess.PIPE)
      acc = 0
      counter = 0
      for line in iter(proc.stdout.readline, ""):
        rtt = float(line.strip())
        if rtt > 0:
          acc += rtt
          counter += 1
      if counter > 0:
        result = f + " " + str(acc / counter * 1000) # millisecond
      print result
      log.write(result + "\n")

  log.close()