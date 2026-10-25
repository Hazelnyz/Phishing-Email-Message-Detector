"""Leakage-conscious email training and evaluation."""
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate, GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from src.data_loader_email import load_email_csv, marker_tokens_from_training, source_marker
from src.evaluation_utils import evaluate, select_threshold, mask_text

ROOT=Path(__file__).resolve().parents[1]
RAW=ROOT/'data/raw/email/Phishing_Email.csv'; INDEP=ROOT/'data/raw/validation/Phishing_validation_emails.csv'
OUT=ROOT/'evaluation'; MODELS=ROOT/'models'; SEED=42

def _scores(model, x): return model.predict_proba(x)[:, list(model.classes_).index(1)]
def _split(frame):
    # Family signature masks likely variable slots while retaining template wording.
    import re
    def family(text):
        text=re.sub(r"https?://\S+|www\.\S+|[\w.+-]+@[\w.-]+", " <slot> ", text)
        text=re.sub(r"\b\d+(?:[./:-]\d+)*\b", " <num> ", text)
        text=re.sub(r"\b[a-z][a-z'-]{2,}\b", lambda m: "<word>" if len(m.group())>9 else m.group(), text)
        return re.sub(r"\s+"," ",text).strip()
    groups=frame.text.map(family)
    # Keep whole families together. Stratified group allocation is approximated
    # with deterministic group shuffles; this avoids body-template leakage.
    gss=GroupShuffleSplit(n_splits=80,test_size=.30,random_state=SEED)
    chosen=None; best=1e9
    for tr,ho in gss.split(frame,frame.label,groups):
        proportions=frame.iloc[ho].label.value_counts(normalize=True)
        score=abs(len(ho)/len(frame)-.30)+abs(proportions.get(0,0)-frame.label.mean())+abs(proportions.get(1,0)-(1-frame.label.mean()))
        if score<best:best=score;chosen=(tr,ho)
    tr,ho=chosen; a=frame.iloc[tr]; b=frame.iloc[ho]
    gss2=GroupShuffleSplit(n_splits=80,test_size=.50,random_state=SEED+1); chosen=None;best=1e9; bg=groups.iloc[ho]
    for va,te in gss2.split(b,b.label,bg):
        props=b.iloc[te].label.value_counts(normalize=True)
        score=abs(len(te)/len(b)-.5)+abs(props.get(0,0)-b.label.mean())+abs(props.get(1,0)-(1-b.label.mean()))
        if score<best:best=score;chosen=(va,te)
    va,te=chosen
    return a.reset_index(drop=True),b.iloc[va].reset_index(drop=True),b.iloc[te].reset_index(drop=True)
def _fit_pair(train, val, stop_words=None):
    vec=TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=160000,stop_words=stop_words,sublinear_tf=True)
    x=vec.fit_transform(train.text); xv=vec.transform(val.text)
    models={"LogisticRegression":LogisticRegression(max_iter=1000,class_weight='balanced',random_state=SEED),"MultinomialNB":MultinomialNB()}
    result={}
    for name,clf in models.items():
        clf.fit(x,train.label)
        scores=_scores(clf,xv); threshold=select_threshold(val.label,scores)
        result[name]=(clf,vec,threshold,evaluate(val.label,scores,threshold)[0])
    return result

def train_email():
    frame, stats=load_email_csv(RAW); train,val,test=_split(frame)
    initial=_fit_pair(train,val)
    from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
    markers={m for m in marker_tokens_from_training(train.text)
             if __import__('re').fullmatch(r"[a-z]{2,}",m) and m not in ENGLISH_STOP_WORDS
             and m not in {"date","from","subject","sent","reply","original","content","message","to","cc","bcc"}}
    # Audit top 30 signed class features for source artifacts before finalization.
    audit={}; found=set()
    for name,(clf,vec,_,_) in initial.items():
        coef=clf.feature_log_prob_ if hasattr(clf,'feature_log_prob_') else clf.coef_
        vocab=np.asarray(vec.get_feature_names_out()); class_features={}
        for ci,label in enumerate((0,1)):
            weights=coef[ci] if coef.shape[0]>1 else (coef[0] if label else -coef[0])
            inds=np.argsort(weights)[-30:][::-1]; feats=[str(vocab[i]) for i in inds]
            class_features['phishing' if label else 'legitimate']=feats
            found.update(f for f in feats if source_marker(f,markers))
        audit[name]=class_features
    final=_fit_pair(train,val,stop_words=sorted(markers)) if found else initial
    selected_name=max(final,key=lambda n:(final[n][3]['f1'],final[n][3]['recall']))
    clf,vec,threshold,val_metrics=final[selected_name]
    candidates={}
    test_scores={}
    for name,(m,v,t,_) in final.items():
        scores=_scores(m,v.transform(test.text)); candidates[name]=evaluate(test.label,scores,t)[0]; test_scores[name]=(scores,(scores>=t).astype(int))
    # grouped CV is unstratified by body-level rows; each row is its normalized text template.
    cv={}
    for name,model in (("LogisticRegression",make_pipeline(TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=160000,sublinear_tf=True),LogisticRegression(max_iter=1000,class_weight='balanced',random_state=SEED))),
                       ("MultinomialNB",make_pipeline(TfidfVectorizer(ngram_range=(1,2),min_df=2,max_features=160000,sublinear_tf=True),MultinomialNB()))):
        cvres=cross_validate(model,frame.text,frame.label,cv=StratifiedKFold(5,shuffle=True,random_state=SEED),scoring=['precision','recall','f1'],n_jobs=1)
        cv[name]={metric:{"mean":float(np.mean(cvres['test_'+metric])),"std":float(np.std(cvres['test_'+metric]))} for metric in ('precision','recall','f1')}
    # Independent validation is evaluation only after model and threshold locked.
    independent,ind_stats=load_email_csv(INDEP,deduplicate=False)
    independent_models={}
    for name,(m,v,t,_) in final.items():independent_models[name]=evaluate(independent.label,_scores(m,v.transform(independent.text)),t)[0]
    indep_metrics=independent_models[selected_name]
    # Existing handwritten hard test set is also untouched until selection is complete.
    hard=pd.read_csv(ROOT/'data/hard_test.csv'); hard_text=hard.message.fillna('').astype(str)
    hard_label=hard.label.map({'legitimate':0,'phishing':1}).astype(int)
    hard_models={}
    for name,(m,v,t,_) in final.items():hard_models[name]=evaluate(hard_label,_scores(m,v.transform(hard_text)),t)[0]
    hard_metrics=hard_models[selected_name]
    hard_pred=( _scores(clf,vec.transform(hard_text))>=threshold).astype(int)
    errors=[]
    def add_errors(setname, texts, ys, probs, preds):
        for text,y,pred,score in zip(texts,ys,preds,probs):
            if int(y)!=int(pred): errors.append({"task":"email","test_set":setname,"true_label":int(y),"predicted_label":int(pred),"score":float(score),"message":mask_text(text)})
    add_errors('hard_test',hard_text,hard_label,_scores(clf,vec.transform(hard_text)),hard_pred)
    add_errors('validation_external',independent.text,independent.label,_scores(clf,vec.transform(independent.text)),( _scores(clf,vec.transform(independent.text))>=threshold).astype(int))
    for name,(scores,preds) in test_scores.items():add_errors('in_distribution_test:'+name,test.text,test.label,scores,preds)
    MODELS.mkdir(exist_ok=True); OUT.mkdir(exist_ok=True)
    joblib.dump(vec,MODELS/'email_vectorizer.joblib'); joblib.dump(clf,MODELS/'email_best_model.joblib')
    info={"model":selected_name,"threshold":threshold,"vectorizer":"email_vectorizer.joblib","classifier":"email_best_model.joblib"}
    (MODELS/'email_best_info.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
    return {"dataset":stats,"split_sizes":{"train":len(train),"validation":len(val),"test":len(test)},"selection":{"selected_model":selected_name,"threshold":threshold,"validation_metrics":val_metrics,"candidates":{n:r[3] for n,r in final.items()},"source_marker_audit_validation_before":{n:r[3] for n,r in initial.items()},"source_marker_audit_validation_after":{n:r[3] for n,r in final.items()}},"test_sets":{"in_distribution":candidates},"cross_validation":cv,"top_features":audit,"source_marker_audit":{"marker_token_count":len(markers),"found_top_markers":sorted(found),"retrained_with_stoplist":bool(found)},"source_marker_stoplist":sorted(markers),"external_validation":{"metrics":indep_metrics,"models":independent_models,"dataset":ind_stats},"hard_test":{"metrics":hard_metrics,"models":hard_models},"errors":errors}

if __name__=='__main__': print(json.dumps(train_email(),indent=2))
