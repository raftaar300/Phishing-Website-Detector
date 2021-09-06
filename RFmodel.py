


import matplotlib.pyplot as plt
import pandas as pd

good_urls = pd.read_csv("good-urls.csv")
phishing_urls = pd.read_csv("phishing-urls.csv")


print(len(good_urls))
print(len(phishing_urls))


urls = good_urls.append(phishing_urls)


urls.head(5)

print(len(urls))
print(urls.columns)

urls = urls.drop(urls.columns[[0,3,5]],axis=1)
print(urls.columns)




urls = urls.sample(frac=1).reset_index(drop=True)


X= urls.drop('label',axis=1)
labels = urls['label']

import random
random.seed(100)
from sklearn.model_selection import train_test_split
X_train, X_test, Y_train, Y_test = train_test_split(X, labels, test_size=0.1, random_state=0)
print(len(X_train),len(X_test),len(Y_train),len(Y_test))
print(Y_train.value_counts())
print(Y_test.value_counts())


# ## Random Forest

from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(X_train,Y_train)
# rf_pred_label = RFmodel.predict(X_test)
#print(list(Y_test)),print(list(rf_pred_label))
#plt.scatter(X_test, Y_test, color ='red')
#plt.plot(X_test, RFmodel.predict(X_test), color = 'blue')
#plt.show()
# return rf_pred_label
# from sklearn.metrics import confusion_matrix,accuracy_score
# cm2 = confusion_matrix(Y_test,rf_pred_label)
# print(cm2)
# print(accuracy_score(Y_test,rf_pred_label))

# Saving the model to a file
import pickle
file_name = "RandomForestModel.sav"
pickle.dump(RFmodel,open(file_name,'wb'))

def predict(data):
	return RFmodel.predict(data)