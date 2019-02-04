# DroidEvolver
We would like to demonstrate that this is only the raw version of the code for the core modules of DroidEvolver. We are doing code cleanup and adding comments to improve code readability. All code will be uploaded soon.

Available code:

1. Model pool construction
2. Classification and evolvement

Upcoming:

1. Preprocessor
2. Feature extraction
3. Vector generation
 
 Requirements:
 
 Pylibol, scipy == 1.1.0, numpy ==1.15.2

To use:

1. Model pool construction

python model_pool_construction.py --starting s

s = directory of initialization data

2. Classification and evovement

python classification_evolvement.py --past p --current c --starting s --low l --high h --buffer b

p = directory of previous data

c = directory of current data

s = directory of initialization data

l = low threshold value

h = high threshold value

b = buffer size
