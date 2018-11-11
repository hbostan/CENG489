#!/usr/bin/python2

import random
import subprocess
import string

MAKE_CMD = "g++ cipher.cpp -o cipher -lcrypto -ldl"
OPENSSL_CMD = "openssl enc -aes-128-cbc -nosalt -K {} -iv {} -in plaintext.txt -out ciphertext"
IV = "00000000000000000000000000000000"
FRM_STR = "{:^3s} {:^18s} => {:^18s}  {:s}"

def Pad(key):
  l = 16-len(key)
  p = l * chr(0)
  return key+p

def GetTestKeys():
  keys = random.sample(list(open("words.txt", "r")), 150)
  keys = [x.strip() for x in keys]
  for i,key in enumerate(keys):
    if len(key)>16:
      replacement = random.choice(keys[100:])
      while(len(replacement)>16):
        replacement=random.choice(keys[100:])
      keys[i] = replacement
  keys[99] = "gastrointestinal"     #Edge Case len=16
  keys[98] = "a"                    #Edge Case len=1
  return list(map(Pad, keys[:100]))

def MakeExecutable():
  cmd=MAKE_CMD.split(" ")
  p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  out, err = p.communicate()
  return len(out)

def GeneratePlaintext():
  size = random.randint(1, 1024)
  text = "".join(random.choice(string.printable) for _ in range(size))
  with open("plaintext.txt", "w") as f:
    f.write(text)
    f.flush()

def GenerateCiphertext(key):
  key = "".join("{:02x}".format(ord(c)) for c in key)
  cmd = OPENSSL_CMD.format(key, IV).split(" ")
  p=subprocess.Popen(cmd, stdout=subprocess.PIPE)
  out, err = p.communicate()

def main():
  if MakeExecutable() != 0:
    print "Compilation failed, run '"+MAKE_CMD+"' and fix your errors until it doesn't output anything"
    exit()
  points = 0
  keys = GetTestKeys()
  print FRM_STR.format("NO", "KEY","OUTPUT","OK?")
  print "---------------------------------------------------"
  for i, key in enumerate(keys):
    #print "Generating Plaintext..."
    GeneratePlaintext()
    #print "Generating Ciphertext..."
    GenerateCiphertext(key)
    #print "Running program..."
    p=subprocess.Popen(["./cipher"], stdout=subprocess.PIPE)
    out, err = p.communicate()
    if out.strip() == key.strip(chr(0)):
      points += 1
      print FRM_STR.format(str(i), key.strip(chr(0)), out.strip(), "+")
    else:
      print FRM_STR.format(str(i), key.strip(chr(0)), out.strip(), "It seems like you messed this one up")
  print "\nYou got {}/100!\n".format(points)

if __name__ == '__main__':
    main()
