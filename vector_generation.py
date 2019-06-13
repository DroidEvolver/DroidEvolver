#!/usr/bin/python
#coding:utf-8
'''
generate 2011.libsvm (i.e., the initialization dataset) from *.feature developed in 2011

label: 1 = malicious, -1 = benign
'''

import sys
import os
import string
import glob
import re
import string
import pickle as pkl
import argparse


def extract_benign(filedir):

	app_feature = pkl.load(open(filedir + '.feature','rb'))

	result = []
	result.append('-1 ')

	for i in range(len(features)):
		if features[i] in app_feature:
			result.append(str(i+1) + ':1 ')

	data.append(result)



def extract_malicious(filedir):

	app_feature = pkl.load(open(filedir + '.feature','rb'))

	result = []
	result.append('1 ')

	for i in range(len(features)):
		if features[i] in app_feature:
			result.append(str(i+1) + ':1 ')

	data.append(result)


def main():

	global features
	features = []
	features = pkl.load(open('feature_set.pkl','rb'))
	features = [feature.strip() for feature in features]
	print 'feature size:', len(features)
	print type(features)


	global data 
	data = []

	# generate initialization dataset

	benign_names = ['--list of benign apps developed in 2011 ---']
	for benign_app in benign_names:
		extract_benign(benign_app, marker)

	malicious_names = ['--list of malicious apps developed in 2011 --']
	for malicious_app in malicious_names:
		extract_malicious(malicious_app, marker)


	data_file = open('2011.libsvm', 'w') # apps developed in 2011 is the initialization dataset

	for item in data:
		data_file.writelines(item)
		data_file.writelines('\n')
	data_file.close()



if __name__ == "__main__":
	main()
