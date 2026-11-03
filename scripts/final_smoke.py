"""Read-only integration smoke check of local FastAPI routes, no external calls."""
import json
from fastapi.testclient import TestClient
from backend.main import app

with TestClient(app) as client:
    health = client.get('/health')
    assert health.status_code == 200 and health.json()['status'] == 'ok'
    valid = client.post('/analyze-url',json={'url':'https://user@192.0.2.1/verify'})
    assert valid.status_code == 200,valid.text
    data = valid.json()
    assert data['sus_score'] == 70 and data['risk_level'] == 'high'
    invalid = client.post('/analyze-url',json={'url':'file:///etc/passwd'})
    assert invalid.status_code == 422,invalid.text
    print(json.dumps({'health':'PASS','url_heuristic':'PASS','invalid_url_rejection':'PASS',
      'score':70,'scope':'FastAPI in-process; no live dashboard/browser verification'},indent=2))
