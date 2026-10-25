"""Train and report on the existing raw corpora without downloading data."""
import contextlib, io, json
import sys
from pathlib import Path
import pandas as pd
from src.train_email import train_email
from src.train_url import train_url
from src.train_email import _split as email_split
from src.data_loader_email import load_email_csv
from src.evaluation_utils import evaluate
from src.url_features import url_features
import joblib

ROOT=Path(__file__).resolve().parent; EVAL=ROOT/'evaluation'

def evaluate_existing_artifacts():
    """Run feature and end-to-end reporting without retraining or reselection."""
    metrics_path=EVAL/'metrics.json'
    metrics=json.loads(metrics_path.read_text(encoding='utf-8'))
    if not (ROOT/'models/email_best_model.joblib').exists():
        raise FileNotFoundError('Saved selected email model is missing; no retraining was requested.')
    model=joblib.load(ROOT/'models/email_best_model.joblib')
    vectorizer=joblib.load(ROOT/'models/email_vectorizer.joblib')
    features=vectorizer.get_feature_names_out(); vocabulary=set(vectorizer.vocabulary_)
    tokens=['enron','2000','2001','2002','2004','2005','vince','mailman','listinfo','linguistics','viagra','click','free','money','offer']
    vocab_check={token:('present' if token in vocabulary else 'absent') for token in tokens}
    class_ids=list(model.classes_)
    if hasattr(model,'feature_log_prob_'):
        class_weights={int(label):model.feature_log_prob_[i] for i,label in enumerate(class_ids)}
    else:
        positive=model.coef_[0]; class_weights={int(class_ids[0]):-positive,int(class_ids[1]):positive}
    top30={}
    for label,name in ((0,'legitimate'),(1,'phishing')):
        inds=class_weights[label].argsort()[-30:][::-1]
        top30[name]=[str(features[i]) for i in inds]
    from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
    from src.data_loader_email import load_email_csv,marker_tokens_from_training
    from src.train_email import _split
    source,_=load_email_csv(ROOT/'data/raw/email/Phishing_Email.csv')
    train,_,id_test=_split(source)
    stoplist={word for word in marker_tokens_from_training(train.text)
              if __import__('re').fullmatch(r'[a-z]{2,}',word) and word not in ENGLISH_STOP_WORDS
              and word not in {'date','from','subject','sent','reply','original','content','message','to','cc','bcc'}}
    generic=sorted({'click','free','money','offer','win','urgent','verify','password'} & stoplist)
    feature_check={'vocabulary_tokens':vocab_check,'top_30_features_per_class_after_stoplist':top30,
                   'generic_phishing_words_in_source_marker_stoplist':generic,
                   'source_marker_stoplist_size':len(stoplist)}
    metrics['email']['final_model_feature_check']=feature_check

    from src.risk_engine import normalize_email_for_model, _probability_to_ml_points
    threshold=float(metrics['email']['selection']['threshold'])
    raw_sample=str(pd.read_csv(ROOT/'data/raw/email/Phishing_Email.csv',usecols=['Email Text']).iloc[0,0] or '')
    normalize_check={'inference_output_equals_evaluation_cleaner':normalize_email_for_model(raw_sample)==__import__('src.data_loader_email',fromlist=['clean_email_text']).clean_email_text(raw_sample),
                     'threshold':threshold,'threshold_maps_to_ml_midpoint':_probability_to_ml_points(threshold,threshold)==25.0}
    metrics['end_to_end_diagnostics']={'ml_points_mapping':'p<=t: 25*p/t; p>t: 25+25*(p-t)/(1-t)','threshold_used_for_risk_points':True,'threshold':threshold,'normalization_check':normalize_check}

    validation,_=load_email_csv(ROOT/'data/raw/validation/Phishing_validation_emails.csv',deduplicate=False)
    hard=pd.read_csv(ROOT/'data/hard_test.csv')
    specs={
        'independent_validation':(validation.text.tolist(),validation.label.astype(int).tolist(),metrics['validation']['metrics']),
        'hard_test':(hard.message.fillna('').astype(str).tolist(),hard.label.map({'legitimate':0,'phishing':1}).astype(int).tolist(),metrics['hard_test']['metrics']),
        'in_distribution_test':(id_test.text.tolist(),id_test.label.astype(int).tolist(),metrics['email']['test_sets']['in_distribution'][metrics['email']['selection']['selected_model']]),
    }
    from src.risk_engine import classify_risk
    from src.evaluation_utils import evaluate
    level_names=['LOW RISK','MEDIUM RISK','HIGH RISK','INSUFFICIENT INFORMATION']
    e2e={}
    for name,(texts,labels,ml_only) in specs.items():
        levels=[classify_risk(text)['risk_level'] for text in texts]
        counts={level:levels.count(level) for level in level_names}
        item={'size':len(texts),'risk_label_distribution':counts,'ml_only_selected_model':ml_only,'views':{}}
        for view,positive_levels in [('medium_or_high',{'MEDIUM RISK','HIGH RISK'}),('high_only',{'HIGH RISK'})]:
            pred=[int(level in positive_levels) for level in levels]
            values,_=evaluate(labels,pred,.5)
            item['views'][view]={key:values[key] for key in ('precision','recall','f1','confusion_matrix')}
        e2e[name]=item
    metrics['end_to_end']=e2e
    metrics_path.write_text(json.dumps(metrics,indent=2,allow_nan=False),encoding='utf-8')

    section=io.StringIO()
    print('FEATURE CHECK AND END-TO-END EVALUATION (REUSED LOCKED ARTIFACTS)',file=section)
    print(f"Final selected email model: {metrics['email']['selection']['selected_model']} | threshold unchanged: {metrics['email']['selection']['threshold']:.4f}",file=section)
    print('Vocabulary presence:',file=section)
    for token,status in vocab_check.items():print(f"{token}: {status}",file=section)
    print('Final top 30 features per class after stoplist:',file=section)
    print(json.dumps(top30,sort_keys=True),file=section)
    print(f"Generic phishing terms found among {len(stoplist):,} source-marker stoplist tokens: {generic}",file=section)
    print(f"ML points after fix: if p<=t then 25*p/t; if p>t then 25+25*(p-t)/(1-t). Validation threshold t={threshold:.4f} maps to 25.0 points and is used in risk scoring.",file=section)
    print(f"Preprocessing check: inference uses clean_email_text; same raw email matches evaluation cleaner: {normalize_check['inference_output_equals_evaluation_cleaner']}.",file=section)
    print('\nEND-TO-END RESULTS (phishing positive; confusion rows=actual, columns=predicted)',file=section)
    for name,result in e2e.items():
        print(f"\n{name} | n={result['size']}",file=section)
        print(f"Risk label distribution: {json.dumps(result['risk_label_distribution'],sort_keys=True)}",file=section)
        ml=result['ml_only_selected_model']
        print(f"ML-only selected model: precision={ml['precision']:.4f} | recall={ml['recall']:.4f} | F1={ml['f1']:.4f} | confusion={json.dumps(ml['confusion_matrix'])}",file=section)
        for view,label in [('medium_or_high','HIGH or MEDIUM counted phishing'),('high_only','HIGH only counted phishing')]:
            row=result['views'][view]
            print(f"{label}: precision={row['precision']:.4f} | recall={row['recall']:.4f} | F1={row['f1']:.4f} | confusion={json.dumps(row['confusion_matrix'])}",file=section)
    existing=(EVAL/'terminal_run.txt').read_text(encoding='utf-8') if (EVAL/'terminal_run.txt').exists() else ''
    marker='\nFEATURE CHECK AND END-TO-END EVALUATION (REUSED LOCKED ARTIFACTS)\n'
    if marker in existing:existing=existing.split(marker,1)[0]
    final=existing.rstrip()+marker+section.getvalue().split('\n',1)[1]
    (EVAL/'terminal_run.txt').write_text(final,encoding='utf-8')
    print(final)

def main():
    EVAL.mkdir(exist_ok=True); report=io.StringIO()
    with contextlib.redirect_stdout(report):
        print('DATASET SIZES AND CLASS BALANCE')
        email_raw=pd.read_csv(ROOT/'data/raw/email/Phishing_Email.csv',usecols=['Email Type'])
        val_raw=pd.read_csv(ROOT/'data/raw/validation/Phishing_validation_emails.csv',usecols=['Email Type'])
        url_raw=pd.read_csv(ROOT/'data/raw/url/PhiUSIIL_Phishing_URL_Dataset.csv',usecols=['label'])
        print(f"email_train_source: {len(email_raw)} | {email_raw['Email Type'].value_counts().to_dict()}")
        print(f"independent_email_validation: {len(val_raw)} | {val_raw['Email Type'].value_counts().to_dict()}")
        print(f"url_source: {len(url_raw)} | raw labels (1=legitimate, 0=phishing): {url_raw.label.value_counts().to_dict()}")
        sms_files=list((ROOT/'data/raw/sms').glob('*.csv')) if (ROOT/'data/raw/sms').exists() else []
        print(f"sms: {'available' if sms_files else 'no CSV files; skipped'}")
        email=train_email(); url=train_url()
        # Inspection only: report the final persisted email model's real vocabulary
        # and top features after the source-marker stoplist was applied.
        email_vec=joblib.load(ROOT/'models/email_vectorizer.joblib')
        email_model=joblib.load(ROOT/'models/email_best_model.joblib')
        vocab=set(email_vec.vocabulary_)
        vocab_tokens=['enron','2000','2001','2002','2004','2005','vince','mailman','listinfo','linguistics','viagra','click','free','money','offer']
        vocabulary_check={token:('present' if token in vocab else 'absent') for token in vocab_tokens}
        names=email_vec.get_feature_names_out()
        classes=list(email_model.classes_)
        final_features={}
        if hasattr(email_model,'feature_log_prob_'):
            weights_by_label={int(label):email_model.feature_log_prob_[i] for i,label in enumerate(classes)}
        else:
            positive=email_model.coef_[0]
            weights_by_label={int(classes[0]):-positive,int(classes[1]):positive}
        for label,name in ((0,'legitimate'),(1,'phishing')):
            weights=weights_by_label[label]
            indices=weights.argsort()[-30:][::-1]
            final_features[name]=[str(names[i]) for i in indices]
        generic_phishing_words={'click','free','money','offer','win','urgent','verify','password'}
        generic_stoplist=sorted(generic_phishing_words & set(email['source_marker_stoplist']))
        email['final_model_feature_check']={'vocabulary_tokens':vocabulary_check,'top_30_features_per_class_after_stoplist':final_features,'generic_phishing_words_in_source_marker_stoplist':generic_stoplist}
        # The stoplist itself is only needed transiently to compute the audit;
        # keep evaluation/metrics.json readable.
        email.pop('source_marker_stoplist',None)
        print(f"email_clean_deduplicated: {email['dataset']['clean_rows']} | labels={email['dataset']['clean_label_counts']}")
        print(f"URL_deduplicated_balanced_sample: {url['dataset']['sample_rows']} | labels={url['dataset']['sample_label_counts']}")
        print('\nSPLIT SIZES')
        print(f"email: {email['split_sizes']} (template-family separated)")
        print(f"URL: {url['split_sizes']} (deduplicated, balanced sample cap 50,000)")
        print('\nFINAL SELECTED EMAIL MODEL FEATURE CHECK (AFTER STOPLIST)')
        print(f"selected_model={email['selection']['selected_model']}")
        for token,status in vocabulary_check.items():print(f"{token}: {status}")
        print('Final top 30 features by class:')
        print(json.dumps(final_features,sort_keys=True))
        print(f"Generic phishing words in the {email['source_marker_audit']['marker_token_count']:,}-token stoplist: {generic_stoplist}")
        print('\nPER-MODEL METRICS BY TEST SET')
        for typ,sets in [('email',email['test_sets']),('url',url['test_sets'])]:
            for setname,models in sets.items():
                print(f"\n{typ} / {setname}")
                for model,result in models.items():
                    print(f"{model}: precision={result['precision']:.4f} | recall={result['recall']:.4f} | F1={result['f1']:.4f}")
                    print('Confusion matrix [actual rows, predicted columns; legitimate, phishing]:')
                    print(json.dumps(result['confusion_matrix']))
        # Independent source and handwritten tests are evaluation-only.
        for testname,results in [('email / independent_validation',email['external_validation']['models']),('email / hard_test',email['hard_test']['models'])]:
            print(f"\n{testname}")
            for model,result in results.items():
                print(f"{model}: precision={result['precision']:.4f} | recall={result['recall']:.4f} | F1={result['f1']:.4f}")
                print('Confusion matrix [actual rows, predicted columns; legitimate, phishing]:')
                print(json.dumps(result['confusion_matrix']))
        # Handwritten domain checks are not used to train/select either model.
        cases=[('https://vit.ac.in/login',0),('https://vtop.vit.ac.in/',0),('http://vit-verify.xyz/login',1),('https://rnicrosoft.com/login',1),('https://xn--pple-43d.com/',1),('https://google.com/',0)]
        domain=[]
        for u,y in cases:
            finding=__import__('src.lookalike',fromlist=['inspect_domain']).inspect_domain(u)
            pred=int(finding['suspicious']);domain.append({'url':u,'label':y,'prediction':pred,'flags':finding['flags']})
        dmetrics,_=evaluate([x[1] for x in cases],[x['prediction'] for x in domain],.5)
        print('\ndomain / handwritten offline cases')
        print(json.dumps(dmetrics,sort_keys=True))
        print('\nSELECTED MODELS AND VALIDATION THRESHOLDS')
        print(f"email: {email['selection']['selected_model']} | {email['selection']['threshold']:.4f}")
        print(f"URL: {url['selection']['selected_model']} | {url['selection']['threshold']:.4f}")
        print('\n5-FOLD CROSS-VALIDATION (email training corpus; fold mean and standard deviation)')
        print(json.dumps(email['cross_validation'],sort_keys=True))
        print('\nTOP EMAIL FEATURES / SOURCE MARKER AUDIT')
        print(json.dumps({'features':email['top_features'],'marker_audit':email['source_marker_audit']},sort_keys=True))
        print('Validation metrics before source-marker stoplist:')
        print(json.dumps(email['selection']['source_marker_audit_validation_before'],sort_keys=True))
        print('Validation metrics after source-marker stoplist:')
        print(json.dumps(email['selection']['source_marker_audit_validation_after'],sort_keys=True))
        print('\nTOP URL IMPORTANCES / UNIVARIATE DIAGNOSTIC')
        print(json.dumps({'top':url['top_features'],'near_perfect_univariate':url['near_perfect_univariate']},sort_keys=True))
        from src.risk_engine import classify_risk
        examples=['gimme ur credit details','send ur card no and cvv to confirm','Please submit the assignment by tonight','Dear student, fee payment last date is 30 Oct, pay via the official portal','Your VIT account will be suspended in 24 hours. Click http://vit-verify.xyz/login now.']
        print('\n5 LIVE EXAMPLE MESSAGES WITH RISK LABELS')
        for message in examples: print(f"{classify_risk(message)['risk_level']}: {message}")
        print('\nEND-TO-END FULL PIPELINE EVALUATION (selected model + rules + risk floor)')
        clean_frame,_=load_email_csv(ROOT/'data/raw/email/Phishing_Email.csv')
        _,_,id_test=email_split(clean_frame)
        validation_frame,_=load_email_csv(ROOT/'data/raw/validation/Phishing_validation_emails.csv',deduplicate=False)
        hard_frame=pd.read_csv(ROOT/'data/hard_test.csv')
        end_to_end={}
        set_specs={
            'independent_validation':(validation_frame.text.tolist(),validation_frame.label.astype(int).tolist(),email['external_validation']['metrics']),
            'hard_test':(hard_frame.message.fillna('').astype(str).tolist(),hard_frame.label.map({'legitimate':0,'phishing':1}).astype(int).tolist(),email['hard_test']['metrics']),
            'in_distribution_test':(id_test.text.tolist(),id_test.label.astype(int).tolist(),email['test_sets']['in_distribution'][email['selection']['selected_model']]),
        }
        level_names=['LOW RISK','MEDIUM RISK','HIGH RISK','INSUFFICIENT INFORMATION']
        for set_name,(texts,labels,ml_only) in set_specs.items():
            levels=[classify_risk(text)['risk_level'] for text in texts]
            counts={level:levels.count(level) for level in level_names}
            result={'size':len(texts),'risk_label_distribution':counts,'ml_only_selected_model':ml_only,'views':{}}
            for view,positive_levels in [('medium_or_high',{'MEDIUM RISK','HIGH RISK'}),('high_only',{'HIGH RISK'})]:
                predictions=[int(level in positive_levels) for level in levels]
                scores,_=evaluate(labels,predictions,0.5)
                result['views'][view]={k:scores[k] for k in ('precision','recall','f1','confusion_matrix')}
            end_to_end[set_name]=result
            print(f"\n{set_name} | n={len(texts)}")
            print(f"Risk distribution: {json.dumps(counts,sort_keys=True)}")
            print(f"ML-only selected model: precision={ml_only['precision']:.4f} | recall={ml_only['recall']:.4f} | F1={ml_only['f1']:.4f} | confusion={json.dumps(ml_only['confusion_matrix'])}")
            for view,label in [('medium_or_high','HIGH or MEDIUM = phishing'),('high_only','HIGH only = phishing')]:
                metric=result['views'][view]
                print(f"{label}: precision={metric['precision']:.4f} | recall={metric['recall']:.4f} | F1={metric['f1']:.4f} | confusion={json.dumps(metric['confusion_matrix'])}")
    text=report.getvalue(); print(text,end=''); (EVAL/'terminal_run.txt').write_text(text,encoding='utf-8')
    # consolidate metrics under stable top-level keys consumed by UI and docs
    # Legacy aliases remain calculated values for existing project tests/docs.
    legacy_results=[]
    for name,validation_metrics in email['selection']['candidates'].items():
        test_result=email['test_sets']['in_distribution'][name]
        legacy_results.append({'model':name,'accuracy':test_result['accuracy'],'precision_phishing':test_result['precision'],'recall_phishing':test_result['recall'],'f1_phishing':test_result['f1'],'confusion_matrix':test_result['confusion_matrix'],'validation':{'f1':validation_metrics['f1'],'recall':validation_metrics['recall']}})
    metrics={'email':email,'url':url,'sms':{'status':'skipped','reason':'No SMS CSV files are present in data/raw/sms.'},'validation':email['external_validation'],'domain':{'status':'handwritten offline cases','metrics':dmetrics,'cases':domain},'hard_test':email['hard_test'],'end_to_end':end_to_end,'train_size':email['split_sizes']['train'],'test_size':email['split_sizes']['test'],'best_model':email['selection']['selected_model'],'threshold':email['selection']['threshold'],'results':legacy_results}
    (EVAL/'metrics.json').write_text(json.dumps(metrics,indent=2,allow_nan=False),encoding='utf-8')
    errors=email['errors']+url.get('errors',[])
    pd.DataFrame(errors,columns=['task','test_set','true_label','predicted_label','score','message']).to_csv(EVAL/'errors.csv',index=False)
    card=f"""# Dataset card\n\nGenerated by `run_pipeline.py`; sizes below come from `evaluation/metrics.json`.\n\n## Sources and use\n\n- Email training corpus: [Phishing Email dataset](https://www.kaggle.com/datasets/subhajournal/phishingemails), listed in third-party records as LGPL-3.0; confirm the originating download terms before redistribution. Email body and label fields only; headers and source artifacts may remain.\n- Independent email validation: [Zenodo record 13474746](https://zenodo.org/records/13474746), 2,000 labeled email texts; record does not specify a license. Used only after selection.\n- URL corpus: [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset), CC BY 4.0. Uses only raw URL and label; 1=legitimate, 0=phishing. No URL is fetched or resolved.\n- SMS: skipped because the raw SMS folder contains no CSV.\n\n## Limitations\n\nEmail source data can contain collection artifacts; template-family splitting and source-marker audits reduce but do not eliminate leakage. The handwritten hard set and domain cases are small, and should not be treated as estimates of production accuracy. URL lexical models cannot inspect page contents. Metrics and sample counts: see the generated `evaluation/metrics.json`.\n"""
    (ROOT/'DATASET_CARD.md').write_text(card,encoding='utf-8')

if __name__=='__main__':
    if '--evaluate-existing' in sys.argv: evaluate_existing_artifacts()
    else: main()
