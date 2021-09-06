
import pandas as pd



good_urls = pd.read_csv("good-urls.csv")
phishing_urls = pd.read_csv("phishing-urls.csv")



urls = good_urls.append(phishing_urls)


# urls.head(5)



urls = urls.drop(urls.columns[[0,3,5]],axis=1)


urls = urls.sample(frac=1).reset_index(drop=True)

X = urls.drop('label',axis=1)
labels = urls['label']

from sklearn.model_selection import train_test_split
X_train, X_test, Y_train, Y_test = train_test_split(X, labels, test_size=0.10, random_state=1)



print(len(X_train),len(X_test),len(Y_train),len(Y_test))



print(Y_train.value_counts())
print(Y_test.value_counts())


from sklearn.metrics import confusion_matrix,accuracy_score,precision_score

print("###########################")
print("Logistic Regression")
from sklearn.linear_model import LogisticRegression
Lr_model = LogisticRegression()
Lr_model.fit(X_train, Y_train)


lr_pred = Lr_model.predict(X_test)




cm = confusion_matrix(Y_test, lr_pred)
print("confusion matrix")
print(cm)

print("accuracy: ", accuracy_score(Y_test, lr_pred))
print("precision: ", precision_score(Y_test, lr_pred))

print("###############################")
print("Decision Tree")
from sklearn.tree import DecisionTreeClassifier
DTmodel = DecisionTreeClassifier()
DTmodel.fit(X_train,Y_train)


pred_label = DTmodel.predict(X_test)




cm1 = confusion_matrix(Y_test,pred_label)
print("confusion matrix")
print(cm1)

print("accuracy: ", accuracy_score(Y_test, pred_label))
print("precision: ", precision_score(Y_test, pred_label))

print("#########################")
print("Random Forest")

from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(X_train,Y_train)


rf_pred_label = RFmodel.predict(X_test)


cm2 = confusion_matrix(Y_test,rf_pred_label)
print("confusion matrix")
print(cm2)


print("accuracy: ", accuracy_score(Y_test, rf_pred_label))
print("precision: ", precision_score(Y_test, rf_pred_label))


# imp_rf_model = RandomForestClassifier(n_estimators=100,max_depth=30,max_leaf_nodes=10000)



# imp_rf_model.fit(X_train,Y_train)

# imp_pred_label = imp_rf_model.predict(X_test)


# cm3 = confusion_matrix(Y_test,imp_pred_label)
# cm3

