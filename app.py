from flask import Flask,render_template,request

import pickle
# import RFmodel
import ExtractFeature
app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/query',methods=['GET','POST'])
def query():
    if request.method == 'POST':
        url = request.form['url']
        print(url)
        data = ExtractFeature.getfeatures(url)
        # print(data)
        # for i in data:
        #     print(data[i])
        RFmodel = pickle.load(open('RandomForestModel.sav', 'rb'))
        pred_value = RFmodel.predict(data)
        print(pred_value)
        if pred_value[0] == 0:    
            msg = "Legitimate"
            return render_template("index.html",error=msg)
        else:
            msg = "Phishing"
            return render_template("index.html",error=msg)
if __name__ == "__main__":
    app.run(debug=True)