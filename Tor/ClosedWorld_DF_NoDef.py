#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This code is to implement deep fingerprinting model for website fingerprinting attacks
# Modified to include sklearn precision, recall, F1 during training

from keras import backend as K
from sklearn.metrics import classification_report, precision_score, recall_score, f1_score
from utility import LoadDataNoDefCW
from Model_NoDef import DFNet
import random
from tensorflow.keras.utils import to_categorical
from keras.optimizers import Adamax
from tensorflow.keras.callbacks import Callback   ### NEW
import numpy as np
import os

random.seed(0)
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

description = "Training and evaluating DF model for closed-world scenario on non-defended dataset"
print(description)

# Training the DF model
NB_EPOCH = 30   # Number of training epoch
print("Number of Epoch: ", NB_EPOCH)
BATCH_SIZE = 128 # Batch size
VERBOSE = 2 # Output display mode
LENGTH = 5000 # Packet sequence length
OPTIMIZER = Adamax(learning_rate=0.002, beta_1=0.9, beta_2=0.999, epsilon=1e-08, decay=0.0) # Optimizer
NB_CLASSES = 81 # number of outputs = number of classes
INPUT_SHAPE = (LENGTH,1)

# Data: shuffled and split between train and test sets
print("Loading and preparing data for training, and evaluating the model")
X_train, y_train, X_valid, y_valid, X_test, y_test = LoadDataNoDefCW()

K.set_image_data_format("channels_last") # tf is tensorflow

# Convert data as float32 type
X_train = X_train.astype('float32')
X_valid = X_valid.astype('float32')
X_test = X_test.astype('float32')
y_train = y_train.astype('float32')
y_valid = y_valid.astype('float32')
y_test = y_test.astype('float32')

# we need a [Length x 1] x n shape as input to the DF CNN (Tensorflow)
X_train = X_train[:, :,np.newaxis]
X_valid = X_valid[:, :,np.newaxis]
X_test = X_test[:, :,np.newaxis]

print(X_train.shape[0], 'train samples')
print(X_valid.shape[0], 'validation samples')
print(X_test.shape[0], 'test samples')

# Store original labels for sklearn metrics
y_test_original = y_test.copy()
y_valid_original = y_valid.copy()

# Convert class vectors to categorical classes matrices
y_train = to_categorical(y_train, NB_CLASSES)
y_valid = to_categorical(y_valid, NB_CLASSES)
y_test = to_categorical(y_test, NB_CLASSES)

# Custom callback for sklearn metrics
class MetricsCallback(Callback):
    def __init__(self, validation_data):
        super().__init__()
        self.validation_data = validation_data

    def on_epoch_end(self, epoch, logs=None):
        val_X, val_y = self.validation_data
        val_pred = self.model.predict(val_X, verbose=0)
        val_pred_classes = np.argmax(val_pred, axis=1)
        val_true_classes = np.argmax(val_y, axis=1)

        precision = precision_score(val_true_classes, val_pred_classes, average='macro')
        recall = recall_score(val_true_classes, val_pred_classes, average='macro')
        f1 = f1_score(val_true_classes, val_pred_classes, average='macro')

        print(f"\nEpoch {epoch+1} - val_precision: {precision:.4f} - val_recall: {recall:.4f} - val_f1: {f1:.4f}")

# Building and training model
print("Building and training DF model")
model = DFNet.build(input_shape=INPUT_SHAPE, classes=NB_CLASSES)

# Compile model (accuracy only)
model.compile(loss="categorical_crossentropy", 
              optimizer=OPTIMIZER,
              metrics=["accuracy"])

print("Model compiled")

# Start training
history = model.fit(X_train, y_train,
                   batch_size=BATCH_SIZE, epochs=NB_EPOCH,
                   verbose=VERBOSE, validation_data=(X_valid, y_valid),
                   callbacks=[MetricsCallback((X_valid, y_valid))])  ### NEW

# Start evaluating model with testing data
score_test = model.evaluate(X_test, y_test, verbose=VERBOSE)
print("Testing accuracy:", score_test[1])

# Method 2: Detailed evaluation using sklearn
print("\n" + "="*50)
print("DETAILED EVALUATION USING SKLEARN")
print("="*50)

# Get predictions
y_pred = model.predict(X_test)
y_pred_classes = np.argmax(y_pred, axis=1)
y_test_classes = y_test_original.astype(int)

# Calculate macro and micro averaged metrics
precision_macro = precision_score(y_test_classes, y_pred_classes, average='macro')
recall_macro = recall_score(y_test_classes, y_pred_classes, average='macro')
f1_macro = f1_score(y_test_classes, y_pred_classes, average='macro')

precision_micro = precision_score(y_test_classes, y_pred_classes, average='micro')
recall_micro = recall_score(y_test_classes, y_pred_classes, average='micro')
f1_micro = f1_score(y_test_classes, y_pred_classes, average='micro')

print("Macro-averaged Precision:", precision_macro)
print("Macro-averaged Recall:", recall_macro)
print("Macro-averaged F1-score:", f1_macro)
print()
print("Micro-averaged Precision:", precision_micro)
print("Micro-averaged Recall:", recall_micro)
print("Micro-averaged F1-score:", f1_micro)

# Detailed per-class report
print("\n" + "="*50)
print("PER-CLASS CLASSIFICATION REPORT")
print("="*50)
print(classification_report(y_test_classes, y_pred_classes, 
                          target_names=[f'Website_{i}' for i in range(NB_CLASSES)]))
