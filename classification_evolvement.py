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
			y_marker += 1

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
	parser.add_argument('--starting', type=int, help='starting year') 
	parser.add_argument('--low', type=float, help='low threshold value')
	parser.add_argument('--high', type=float, help='high threshold value')
	parser.add_argument('--buffer', type=int, help = 'buffer size value')

	args = parser.parse_args()

	buffer_size = args.buffer
	age_threshold_low = args.low
	age_threshold_up = args.high



	whole_directory = './'+ str(args.starting) + 'train/'
	current_directory = str(age_threshold_low) + '_' + str(age_threshold_up) + '_' + str(buffer_size) + '/' 
	checkpoint_dir = whole_directory + current_directory
	if not os.path.exists(checkpoint_dir):
		os.makedirs(checkpoint_dir)

	# record all evolving result to a file
	Result = open(whole_directory + str(args.starting) + '.evolving_result','a')
	evolving_result = []
	evolving_result.append(str(args.past) + ' ' + str(args.current) + ' ' + str(age_threshold_low) + ' ' + str(age_threshold_up) + ' ' + str(buffer_size) + ' ' + str(model_number) + ' ')
	

	print 'Loading data from ', args.past # old dataset
	X_train,Y_train=load_svmlight_file( str(args.past))
	print 'X_train data shape' , type(X_train), X_train.shape

	print 'Loading test data from ', args.current # new dataset
	X_test,Y_test=load_svmlight_file(str(args.current))
	X_testt,Y_testt=load_svmlight_file( str(args.current))

	print 'X_test data shape', type(X_test), X_test.shape
	xtest_dense = scipy.sparse.csr_matrix(X_testt).todense()
	print 'X_test', xtest_dense.shape

	global clfs

	clfs = [PA1(), OGD(), AROW(), RDA(), ADA_FOBOS()]


	print 'model pool size: ', len(clfs)
	ori_train_acc, ori_test_acc, weights, pool_acc, pool_fscore, pool_precision, pool_tpr, pool_fnr, pool_fpr, pool_difference = ([] for i in range(10))

	print 'Loading trained model from ', args.past

	if args.starting == args.past: # copy the original detection model into checkpoint_dir
		for i in xrange(len(clfs)):
			shutil.copy2( whole_directory + str(args.past) + '_' + str(i) + '.model' , checkpoint_dir )

	for i in xrange(len(clfs)):

		clfs[i].load( checkpoint_dir + str(args.past) + '_' + str(i) + '.model')
		# get original model weight
		w = clfs[i].coef_[1:]

		weight = [] # [i][j]: i = model index, j = feature index
		for w_num in xrange(len(w)):
			weight.append(w[w_num])
		weights.append(weight)

		test_accuracy,auc,tpr_fig,fpr_fig=clfs[i].score(X_test,Y_test,False)
		ori_test_acc.append(test_accuracy)

	print 'original weight size'
	for c in xrange(len(weights)):
		print c, len(weights[c])

	print 'App buffer generation'
	global app_buffer
	app_buffer = [] 
	if '2011' in str(args.past): # buffer is not exist
		print 'App buffer not exists'
		print 'App buffer initialization'
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
	confidences, new_confidences, p_values, instances, model_credits, model_confidences = ([] for i in range(6))
	all_fail = 0 # a special case, all model are aged
	num_of_update = num_of_update_model =  0
	wrong_update = 0
	wrong_update_benign = wrong_update_malicious = right_update_benign = right_update_malicious = 0

	for i in xrange(len(Y_test)): # i = every app

		pre, conf, new_conf, app_b, p_value = ([] for i in range(5))

		for j in xrange(len(clfs)):
			xtest_current = xtest_dense[i, :len(weights[j])] 
			score = xtest_current.dot(weights[j])
			conf.append(score[0,0])
			app_b.append(score[0,0])
			new_conf.append(abs(score[0,0]))

		confidences.append(conf)
		new_confidences.append(new_conf)
		app_buffer[random.randint(0, buffer_size-1)] = app_b # randomly replace a processed app with new app


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


		# update aged models
		if (aged_marker != 0) and (young_marker >= 1): # drifting app is identified and young model exists

			update_label = np.array([instances[i].pl]) 
			update_with_pseudo_label += 1

			for model_index in aged_model: # update clfs[a] with X_test[i], temp.pl; a is the aged model index
				num_of_update_model += 1

				# update with drifting app and corresponding pseudo label
				train_accuracy,data,err,fit_time=clfs[model_index].fit(X_test[i],update_label, False)
				w = clfs[model_index].coef_[1:] 
				updated_w = []
				for w_num in xrange(len(w)):
					updated_w.append(w[w_num])
				weights[model_index] = updated_w


	print 'update with pseudo label ', update_with_pseudo_label

	a, f, preci, tprr, fprr = evaluation(Y_test, instances)
	pool_acc.append(a)
	pool_fscore.append(f)
	pool_precision.append(preci)
	pool_tpr.append(tprr)
	pool_fnr.append(100-tprr)
	pool_fpr.append(fprr)


	print buffer_size, len(app_buffer)
	print 'original test accuracy',ori_test_acc # without evolving
	print 'pool accuracy', pool_acc
	print 'pool fscore', pool_fscore
	print 'pool precision', pool_precision
	print 'pool tpr', pool_tpr
	print 'pool fnr', pool_fnr
	print 'pool fpr', pool_fpr
	print 'pool_fnr - pool_fpr', pool_difference

	print 'evolved weight length'
	for c in xrange(len(weights)):
		print c, len(weights[c])

	print 'Save model evolved in Year ', args.current, 'into directory /', checkpoint_dir
	current_year = args.current
	save_model(current_year, checkpoint_dir)

	print 'Save app buffer evolved in Year', args.current
	pkl.dump(app_buffer, open( checkpoint_dir + str(args.current) + '_buffer.pkl', 'wb'))

	evolving_result.append(str(pool_acc) + ' ' + str(pool_fscore) + ' ' + str(pool_precision) + ' ' + str(pool_tpr) + ' ' + str(pool_fnr))
	Result.writelines(evolving_result)
	Result.writelines('\n')

if __name__ == "__main__":
	main()