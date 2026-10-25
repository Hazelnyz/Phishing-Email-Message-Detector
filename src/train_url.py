"""URL-string-only classification; no network or website-derived inputs."""
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from src.url_features import url_features
from src.evaluation_utils import evaluate,select_threshold,mask_text

ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/'data/raw/url/PhiUSIIL_Phishing_URL_Dataset.csv'; OUT=ROOT/'evaluation'; MODELS=ROOT/'models'; SEED=42

def load_url_data(path=DATA,max_per_class=25000):
    frame=pd.read_csv(path,usecols=['URL','label'])
    counts={str(int(k)):int(v) for k,v in frame.label.value_counts().sort_index().items()}
    if counts!={'0':100945,'1':134850}:raise AssertionError(f"Unexpected PhiUSIIL raw label counts: {counts}")
    frame=frame.dropna(subset=['URL']).copy(); frame.URL=frame.URL.astype(str).str.strip(); frame=frame[frame.URL.ne('')]
    frame['label']=(frame.label.astype(int)==0).astype('int8')
    frame=frame.drop_duplicates('URL').reset_index(drop=True)
    frame=pd.concat([g.sample(min(len(g),max_per_class),random_state=SEED) for _,g in frame.groupby('label')]).sample(frac=1,random_state=SEED).reset_index(drop=True)
    return frame,counts

def train_url():
    frame,raw_counts=load_url_data(); a,b=train_test_split(frame,test_size=.30,random_state=SEED,stratify=frame.label); val,test=train_test_split(b,test_size=.5,random_state=SEED,stratify=b.label)
    feats=[url_features(v) for v in frame.URL]; dv=DictVectorizer(sparse=True); X=dv.fit_transform(feats); idx={v:i for i,v in enumerate(frame.URL)}
    def select(df):return X[[idx[v] for v in df.URL]]
    train,val,test=map(lambda x:x.reset_index(drop=True),(a,val,test)); models={'LogisticRegression':LogisticRegression(max_iter=1000,class_weight='balanced',random_state=SEED),'RandomForest':RandomForestClassifier(n_estimators=160,min_samples_leaf=2,class_weight='balanced_subsample',n_jobs=-1,random_state=SEED,max_features='sqrt')}
    fitted={};
    for name,model in models.items():
        model.fit(select(train),train.label); probs=model.predict_proba(select(val))[:,1]; threshold=select_threshold(val.label,probs); fitted[name]=(model,threshold,evaluate(val.label,probs,threshold)[0])
    best=max(fitted,key=lambda n:(fitted[n][2]['f1'],fitted[n][2]['recall'])); model,threshold,_=fitted[best]
    per={}
    errors=[]
    for name,(m,t,_) in fitted.items():per[name]=evaluate(test.label,m.predict_proba(select(test))[:,1],t)[0]
    from src.evaluation_utils import mask_text
    for name,(m,t,_) in fitted.items():
        scores=m.predict_proba(select(test))[:,1];preds=(scores>=t).astype(int)
        for raw,y,pred,score in zip(test.URL,test.label,preds,scores):
            if int(y)!=int(pred):errors.append({'task':'url','test_set':'in_distribution_test:'+name,'true_label':int(y),'predicted_label':int(pred),'score':float(score),'message':mask_text(raw)})
    # Univariate validation AUC diagnostic only, not a selection source.
    valx=select(val).toarray(); names=dv.get_feature_names_out(); univariate=[]
    for j,n in enumerate(names):
        if np.std(valx[:,j])==0:continue
        try:auc=roc_auc_score(val.label,valx[:,j]);auc=max(auc,1-auc)
        except ValueError:continue
        univariate.append({'feature':str(n),'auc':float(auc)})
    univariate.sort(key=lambda x:x['auc'],reverse=True)
    importances=getattr(model,'feature_importances_',None)
    if importances is None:importances=np.abs(model.coef_[0])
    top=sorted(zip(names,importances),key=lambda x:float(x[1]),reverse=True)[:30]
    urlvec=DictVectorizer(sparse=True); urlvec.fit(feats)
    MODELS.mkdir(exist_ok=True); joblib.dump(urlvec,MODELS/'url_vectorizer.joblib');joblib.dump(model,MODELS/'url_best_model.joblib')
    (MODELS/'url_best_info.json').write_text(json.dumps({'model':best,'threshold':threshold},indent=2),encoding='utf-8')
    return {'dataset':{'raw_rows':sum(raw_counts.values()),'raw_label_counts':raw_counts,'sample_rows':len(frame),'sample_label_counts':{str(int(k)):int(v) for k,v in frame.label.value_counts().items()}},'split_sizes':{'train':len(train),'validation':len(val),'test':len(test)},'selection':{'selected_model':best,'threshold':threshold,'validation_metrics':fitted[best][2],'candidates':{n:v[2] for n,v in fitted.items()}},'test_sets':{'in_distribution':per},'top_features':[{'feature':str(n),'importance':float(v)} for n,v in top],'univariate_validation':univariate[:30],'near_perfect_univariate':[x for x in univariate if x['auc']>=.995],'errors':errors}

if __name__=='__main__':print(json.dumps(train_url(),indent=2))
