import pickle as pkl 
import os
import sys

def main():

	feature = []

	names = ['--list of app names developed in 2011 ----']
	for app_name in names:
		app_feature = pkl.load(open(app_name + '.feature', 'rb'))
		for item in app_feature:
			if item not in feature:
				feature.append(item)

	with open('feature_set.pkl','wb') as result:
		pkl.dump(feature, result)



if __name__ == "__main__":
	main()