# DroidEvolver

 Requirements:
 
 Pylibol, scipy == 1.1.0, numpy ==1.15.2

To use:

STEP 1:

python feature_extraction.py

Extract all detection features from applications

STEP 2:

python feature_set_initialization.py

Initialize the feature set according to initialization dataset

STEP 3:

python vector_generation.py

Generate feature vector for the initialization dataset

STEP 4:

python model_pool_construction.py

Initialize the mode pool using the feature vector of the initialization feature vector

STEP 5:

python classification_evolvement.py --past p --current c --starting s --low l --high h --buffer b

p = directory of previous data

c = directory of current data

s = directory of initialization data

l = low threshold value

h = high threshold value

b = buffer size
