from pathlib import Path
import pandas as pd
from src.data_loader_email import clean_email_text, load_email_csv
from src.url_features import url_features
from src.lookalike import inspect_domain, registered_domain

def test_email_cleaning_and_dedup_before_split(tmp_path):
    p=tmp_path/'e.csv'
    pd.DataFrame({'Email Text':['<b>Hello , WORLD!</b>','<b>Hello , WORLD!</b>','   '], 'Email Type':['Safe Email','Safe Email','Phishing Email']}).to_csv(p,index=False)
    frame,stats=load_email_csv(p)
    assert frame.text.tolist()==['hello, world!']
    assert stats['exact_duplicates_removed']==1
    assert clean_email_text('X'*5100)==('x'*5000)

def test_url_features_are_derived_from_raw_string():
    f=url_features('http://192.0.2.1/a?x=2')
    assert f['has_ip_host']==1 and f['https']==0 and f['path_depth']==1
    assert url_features('https://example.com')['https']==1

def test_lookalike_domain_checks_are_offline_and_suffix_aware():
    assert registered_domain('portal.vit.ac.in')=='vit.ac.in'
    assert not inspect_domain('https://vit.ac.in/login')['suspicious']
    assert inspect_domain('https://rnicrosoft.com/login')['suspicious']
    assert inspect_domain('https://xn--pple-43d.com')['suspicious']

def test_email_model_inference_uses_training_cleaner():
    from src.risk_engine import normalize_email_for_model
    raw='<b>  HELLO , World!</b>'
    assert normalize_email_for_model(raw)==clean_email_text(raw)

def test_validation_threshold_maps_to_ml_midpoint_monotonically():
    from src.risk_engine import _probability_to_ml_points
    t=.17
    assert _probability_to_ml_points(t,t)==25
    assert _probability_to_ml_points(0,t)==0
    assert _probability_to_ml_points(1,t)==50
    assert _probability_to_ml_points(.1,t)<25<_probability_to_ml_points(.5,t)

def test_pipeline_metrics_json_runtime_route():
    from app import app
    client=app.test_client()
    response=client.get('/api/metrics')
    assert response.status_code in (200,404)
    if response.status_code==200:
        assert {'email','url','sms','validation','domain','hard_test'} <= set(response.get_json())
