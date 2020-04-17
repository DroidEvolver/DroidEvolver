'''
Use the model pool initialized with 2011 apps to detect malware from apps developed in 2012, 2013, 2014, 2015, 2016
Model pool and feature set (i.e., feature_set.pkl) are evolved during detection.

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
import pickle as pkl
import argparse
import shutil

class app(object):
	def __init__(self, a, y, pl):
		self.a = a
		self.y = y
		self.pl = pl

def extract_benign(filedir):

	app_feature = pkl.load(open(filedir + '.feature','rb'))

	result = []
	result.append('-1 ')
	new = []
	for i in range(len(features)):
		if features[i] in app_feature:
			result.append(str(i+1) + ':1 ')

	for item in app_feature:
		if item not in features: # this is a new feature, store new features in advance to save time
			p = 1
			# append the new feature to the data
			# the model won't process this new feature unless update 
			# the model will only process the first |len(features)| features
			result.append(str(len(features) + p) + ':1 ') 
			new.append(item)
			p += 1

	return result, new



def extract_malicious(filedir):

	app_feature = pkl.load(open(filedir + '.feature','rb'))

	result = []
	result.append('1 ')
	new = []

	for i in range(len(features)):
		if features[i] in app_feature:
			result.append(str(i+1) + ':1 ')

	for item in app_feature:
		if item not in features: # this is a new feature
			p = 1
			# append the new feature to the data
			# the model won't process this new feature unless update 
			# the model will only process the first |len(features)| features
			# if this app is a drifting app, the new identified feature will be added into feature_set.pkl
			result.append(str(len(features) + p) + ':1 ') 
			new.append(item)
			p += 1

	return result, new


def evaluation(Y_test, instances):
	n = p = tp = fn = tn = fp = right = 0
	print 'evaluating predictions'

	for e in xrange(len(Y_test)):

		if Y_test[e] != 1 and instances[e].pl != 1: # true label, prediction label
			n += 1
			tn += 1
		if Y_test[e] != 1 and instances[e].pl == 1:
			n += 1
			fp +=1
		if Y_test[e] == 1 and instances[e].pl == 1:
			p += 1
			tp += 1
		if Y_test[e] == 1 and instances[e].pl != 1:
			p += 1
			fn += 1
		if Y_test[e] == instances[e].pl:
			right += 1

	print type(Y_test), len(Y_test)
	print 'all', n+p, 'right', right ,'n', n , 'p:', p, 'tn', tn, 'tp',tp, 'fn',fn, 'fp',fp
	accu = (Decimal(tp) + Decimal(tn))*Decimal(100) / (Decimal(n) + Decimal(p))
	tpr = Decimal(tp)*Decimal(100)/Decimal(p)
	fpr = Decimal(fp)*Decimal(100)/Decimal(n)
	f1 = Decimal(200)*Decimal(tp)/(Decimal(2)*Decimal(tp) + Decimal(fp) + Decimal(fn))
	precision = Decimal(tp)*Decimal(100)/(Decimal(tp) + Decimal(fp))
	print 'model pool f measure: ', float(format(f1, '.2f')), 'precision: ', float(format(precision, '.2f')), 'recall: ', float(format(tpr, '.2f'))

	return float(format(accu, '.2f')), float(format(f1, '.2f')), float(format(precision, '.2f')), float(format(tpr, '.2f')), float(format(fpr, '.2f'))


def metric_calculation(i, j, buffer_size):
	larger = 0
	if len(app_buffer) <=buffer_size:
		app_temp = [item[j] for item in app_buffer]
		positive = sum(app_tt > 0 for app_tt in app_temp)
		negative = sum(app_tt <= 0 for app_tt in app_temp) 
		if confidences[i][j] > 0: # prediction label = 1 = malicious
			larger = sum(confidences[i][j] >= app_t and app_t > 0 for app_t in app_temp)
			p_ratio = float(Decimal(larger)/Decimal(positive))

		else: # <= 0 = benign
			larger = sum(confidences[i][j] <= app_t and app_t <= 0 for app_t in app_temp)
			p_ratio = float(Decimal(larger)/Decimal(negative))

	else: 
		app_temp = [item[j] for item in app_buffer[len(app_buffer)-buffer_size:]] 
		positive = sum(app_tt > 0 for app_tt in app_temp) 
		negative = sum(app_tt <= 0 for app_tt in app_temp)
		if confidences[i][j] > 0: # prediction label = 1 = malicious
			larger = sum(confidences[i][j] >= app_t and app_t > 0 for app_t in app_temp)
			p_ratio = float(Decimal(larger)/Decimal(positive))

		else:
			larger = sum(confidences[i][j] <= app_t and app_t <= 0 for app_t in app_temp)
			p_ratio = float(Decimal(larger)/Decimal(negative))
	return p_ratio


def all_model_label(i, age_threshold_low, age_threshold_up):
	young = aged = a_marker = y_marker = 0
	for j in xrange(len(clfs)):
		if age_threshold_low <= p_values[i][j] <= age_threshold_up: # not an aged model, can vote
			young += confidences[i][j]
			y_marker += 1 # number of young model

		else: # this is an aged model, need to be updated
			aged += confidences[i][j]
			aged_model.append(j) # record aged model index
			a_marker += 1 # num of aged model for this drifting app

	return young, aged, a_marker, y_marker


def generate_pseudo_label(aged_marker, young_marker, aged_value, young_value):
	if young_marker == 0: # young models are not available; weighted voting using aged model
		if aged_value > 0:
			temp = app(aged_marker, young_marker, 1.)
		else:
			temp = app(aged_marker, young_marker, -1.)
		fail += 1
	else: # young models are available; weighted voting using young model
		if young_value > 0:
			temp = app(aged_marker, young_marker, 1.)
		else:
			temp = app(aged_marker, aged_marker, -1.)
	instances.append(temp)


def save_model(current_year, checkpoint_dir):
	for m in xrange(len(clfs)):
		print m, clfs[m]
		clfs[m].save( checkpoint_dir + str(current_year) + '_' + str(m) + '.model')


def main():

	# set argument for past year and current year
	parser = argparse.ArgumentParser()
	parser.add_argument('--past', type=int, help='past year')
	parser.add_argument('--current', type=int, help='current year')
	parser.add_argument('--starting', type=int, help='starting year') # initialization year = 2011
	parser.add_argument('--low', type=float, help='low threshold value')
	parser.add_argument('--high', type=float, help='high threshold value')
	parser.add_argument('--buffer', type=int, help = 'buffer size value')

	args = parser.parse_args()

	buffer_size = args.buffer
	age_threshold_low = args.low
	age_threshold_up = args.high


	global features
	features = pkl.load(open('feature_set.pkl','rb'))

	whole_directory = './'+ str(args.starting) + 'train/'
	current_directory = str(age_threshold_low) + '_' + str(age_threshold_up) + '_' + str(buffer_size) + '/' 
	checkpoint_dir = whole_directory + current_directory
	if not os.path.exists(checkpoint_dir):
		os.makedirs(checkpoint_dir)


	global clfs

	clfs = [PA1(), OGD(), AROW(), RDA(), ADA_FOBOS()]
	print 'model pool size: ', len(clfs)

	ori_train_acc, ori_test_acc, weights, pool_acc, pool_fscore, pool_precision, pool_tpr, pool_fnr, pool_fpr, pool_difference = ([] for list_number in range(10))

	print 'Loading trained model from ', args.past

	if args.starting == args.past: # copy the initial detection model into checkpoint_dir
		for i in xrange(len(clfs)):
			shutil.copy2( whole_directory + str(args.past) + '_' + str(i) + '.model' , checkpoint_dir )


	for i in xrange(len(clfs)): # for each model in the model pool

		clfs[i].load( checkpoint_dir + str(args.past) + '_' + str(i) + '.model')
		# get original model weight
		w = clfs[i].coef_[1:]

		weight = [] # [i][j]: i = model index, j = feature index
		for w_num in xrange(len(w)):
			weight.append(w[w_num])
		weights.append(weight)


	print 'original weight size'
	for c in xrange(len(weights)):
		print c, len(weights[c])

	print 'App buffer generation'
	global app_buffer
	app_buffer = []

	if '2011' in str(args.past): # buffer is not exist
		print 'App buffer not exists'
		print 'App buffer initialization'

		print 'Loading data from ', args.past, ' to initialize app buffer ...' # load the 2011 data to initialized app buffer
		X_train,Y_train=load_svmlight_file( str(args.past) + '.libsvm')
		train_size, _  = X_train.shape

		random_app_index = np.random.randint(train_size, size = buffer_size)
		X_train_temp = X_train[random_app_index, :]

		for i in xrange(buffer_size):
			app_buffer_temp = []
			for j  in xrange(len(clfs)):
				app_buffer_temp.append(clfs[j].decision_function(X_train_temp[i])[0])
			app_buffer.append(app_buffer_temp)

	else: # load buffer from str(args.past).buffer
		print 'App buffer exists'
		app_buffer = pkl.load(open( checkpoint_dir + str(args.past) + '_buffer.pkl', 'rb'))
		print 'Load app buffer from ', args.past, '_buffer.pkl'

	print 'Start evolving'
	global confidences, new_confidences, p_values, instances, model_credits, model_confidences
	confidences, new_confidences, p_values, instances, model_credits, model_confidences = ([] for list_number in range(6))
	all_fail = 0 # a special case, all model are aged
	num_of_update = num_of_update_model =  0
	wrong_update = 0
	wrong_update_benign = wrong_update_malicious = right_update_benign = right_update_malicious = 0

	Y_test = [] # save ground truth of test data ; for final evaluation only

	names = ['---list of test app names -----'] # names of apps developed in the current_year, e.g., names of apps developed in 2012
	for i in xrange(len(names)):

		# generate test data

		app_name = names[i] # for each test app
		# according to the ground truth to get the true label
		# the true label is for evaluation only, won't be processed by the model
		data = []
		if 'malicious' in app_name:

			d, new_feature = extract_malicious(app_name)
			data.append(d)
		else:
			d, new_feature = extract_benign(app_name)
			data.append(d)

		# skip if do not need to save test data
		save_data = open(app_name + '.libsvm', 'w')
		for item in data:
			save_data.writelines(item)
			save_data.writelines('\n')
		data_file.close()


		X_test, y_t=load_svmlight_file(app_name + '.libsvm')
		X_testt,y_testt=load_svmlight_file(app_name + '.libsvm')
		Y_test.append(y_t)

		print 'X_test data shape', type(X_test), X_test.shape
		xtest_dense = scipy.sparse.csr_matrix(X_testt).todense()
		print 'X_test', xtest_dense.shape	


		# calculate JI value

		pre, conf, new_conf, app_b, p_value = ([] for list_number in range(5))

		for j in xrange(len(clfs)):
			xtest_current = xtest_dense[ ,:len(weights[j])] 
			score = xtest_current.dot(weights[j])
			conf.append(score[0,0])
			app_b.append(score[0,0])
			new_conf.append(abs(score[0,0]))

		confidences.append(conf)
		new_confidences.append(new_conf)
		app_buffer[random.randint(0, buffer_size-1)] = app_b # randomly replace a processed app with the new app


		for j in xrange(len(clfs)):
			pv = metric_calculation(i, j, buffer_size)
			p_value.append(pv)
		p_values.append(p_value) 


		global aged_model
		aged_model = [] # store the index of aged model for current app i
		young_value = aged_value = aged_marker = young_marker = 0
		young_value, aged_value, aged_marker, young_marker = all_model_label(i, age_threshold_low, age_threshold_up)

		# generate  pseudo label
		generate_pseudo_label(aged_marker, young_marker, aged_value, young_value)

		# drifting app is identified and young model exists
		if (aged_marker != 0) and (young_marker >= 1): 

			update_label = np.array([instances[i].pl]) # update label = pseudo label of the drifting app

			# update aged models
			for model_index in aged_model: # update clfs[a] with X_test, update_label; a is the aged model index
				# update with drifting app and corresponding pseudo label
				train_accuracy,data,err,fit_time=clfs[model_index].fit(X_test,update_label, False)
				w = clfs[model_index].coef_[1:] 
				updated_w = []
				for w_num in xrange(len(w)):
					updated_w.append(w[w_num])
				weights[model_index] = updated_w # update weight matrix in the weight matrix list for the next new app

			# updat feature set
			for new_identified_feature in new_feature:
				features.append(new_identified_feature)


	a, f, preci, tprr, fprr = evaluation(Y_test, instances)
	pool_acc.append(a)
	pool_fscore.append(f)
	pool_precision.append(preci)
	pool_tpr.append(tprr)
	pool_fnr.append(100-tprr)
	pool_fpr.append(fprr)


	print buffer_size, len(app_buffer)
	print 'pool accuracy', pool_acc
	print 'pool fscore', pool_fscore
	print 'pool precision', pool_precision
	print 'pool tpr', pool_tpr
	print 'pool fnr', pool_fnr
	print 'pool fpr', pool_fpr

	print 'evolved weight length'
	for c in xrange(len(weights)):
		print c, len(weights[c])

	# save evolved model for each year
	print 'Save model evolved in Year ', args.current, 'into directory /', checkpoint_dir
	current_year = args.current
	save_model(current_year, checkpoint_dir)


	# save feature set
	with open('feature_set.pkl','wb') as feature_result:
		pkl.dump(features, feature_result)

	print 'Save app buffer evolved in Year', args.current
	pkl.dump(app_buffer, open( checkpoint_dir + str(args.current) + '_buffer.pkl', 'wb'))


if __name__ == "__main__":
	main()
