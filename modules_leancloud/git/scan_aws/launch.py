#!/usr/bin/env python3

import sys
import os

def check_smtp(liste: str):
	if not os.path.exists("smtp"):
		os.mkdir("smtp")
	os.system("bash ses_checker.sh "+liste)

def check_aws(liste: str):
	if not os.path.exists("panel"):
		os.mkdir("panel")
	os.system("bash aws_checker.sh "+liste)

try:
	liste = str(sys.argv[1])
	print("1) check create panel permission + auto create panel credentials (key:secret:region list)")
	print("2) check smtp permissions and quota + auto create smtp credentials (key:secret:region list)")
	selection=int(input("Please select: "))
	if (selection != 1 and selection != 2):
		print("Invalid selection")
		exit(84)
	switch = {
		1: check_aws,
		2: check_smtp
	}
	switch.get(selection)(liste)
except (IndexError, ValueError) as e:
		print("No file specified or invalid selection")
		exit(84)
exit(0)
