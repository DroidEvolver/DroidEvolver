'''
Construct model pool according to initialization dataset, e.g., apps developed in 2011

'''
import pylibol
import numpy as np
import scipy
from scipy.stats import logistic
from scipy.special import expit
from numpy import dot
import sklearn
from sklearn.datasets import load_svmlight_file
import os
import sys
import string
from decimal import *
import collections
from pylibol import classifiers
from classifiers import *
import time
import random
import argparse

def main():

	parser = argparse.ArgumentParser()
	parser.add_argument('--starting', type=int, help='initialization dataset') # to use = args.initialization
	args = parser.parse_args()

	starting_year = args.starting

	X_train,Y_train=load_svmlight_file(str(starting_year) + '.libsvm')
	print 'X_train data shape' , type(X_train), X_train.shape

	global clfs

	clfs = [PA1(), OGD(), AROW(), RDA(), ADA_FOBOS()]

	print 'model pool size: ', len(clfs) # number of models in the model pool

	ori_train_acc = []

	directory = './' + str(starting_year) + 'train/' 
	if not os.path.exists(directory):
		os.makedirs(directory)

	# initialization process of all models 
	print 'All model initialization'
	for i in xrange(len(clfs)): # i = every model in model pool
		print clfs[i]
		print 'training'
		train_accuracy,data,err,fit_time=clfs[i].fit(X_train,Y_train, False)
		ori_train_acc.append(train_accuracy)
		clfs[i].save('./' + str(starting_year) + 'train/' + str(starting_year) + '_' + str(i) + '.model')

	print 'original model accuracy', ori_train_acc

if __name__ == "__main__":
	main()
