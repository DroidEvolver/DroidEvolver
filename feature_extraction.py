'''
Extract detection feature for each app according to included Android API

input: smali files of an app stored under /app_name/
output: detection features for the app stored in app_name.feature

'''
import os
import sys
import string
import pickle as pkl
import argparse
import glob
import operator

def extract_feature(filedir):
	feature = []
	for dirpath, dirnames, filenames in os.walk(filedir):
		for filename in [f for f in filenames if f.endswith ('.smali')]:
			fn = os.path.join(dirpath, filename) # each smali file
			lines = open(fn,'r').readlines()
			lines = [line.strip() for line in lines]

			for line in lines:
				# get all class names in invoke
				try:
					start = line.index(', ') + len(', ')
					end = line.index(';', start)
					classes = line[start:end]
				except ValueError:
					classes = ''

				# get invoking method name
				try:
					start = line.index(';->') + len(';->')
					end = line.index('(', start)
					methods = line[start:end]
				except ValueError:
					methods = ''

				objects = classes.split('/')
				a = len(objects)
				current_class = classes[:-(len(objects[a-1])+1)]

				if current_class in packages: # android api

					fe = classes + ':' + methods
					feature.append(fe)

	with open(filedir + '.feature', 'wb') as result:
		pkl.dump(feature, result)


def main():

	family = ['android','google','java','javax', 'xml','apache', 'junit','json', 'dom']
	# correspond to the android.*, com.google.*, java.*, javax.*, org.xml.*, org.apache.*, junit.*, org.json, and org.w3c.dom.* packages

	global packages
	packages = open('android_package.name','r').readlines()
	packages = [package.strip() for package in packages] # packages correspond to family
	print 'official package number:', len(packages)

	names = ['--list of app names ----']
	for app_name in names:
		extract_feature(app_name)


if __name__ == "__main__":
	main()