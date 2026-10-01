import sys
import os
sys.path.insert(0, os.path.abspath('.'))

import app
from database.database import get_db
from database.models import API, APIDriftEvent

test_app = app.create_app('development')
with test_app.app_context():
    db = get_db()
    apis = db.query(API).all()
    print(f"Total APIs in DB: {len(apis)}")
    for a in apis:
        print(f"  -> ID: {a.id}, Name: '{a.name}', Environment: '{a.environment}', Version: '{a.version}', Endpoints: {len(a.endpoints)}")
    
    drifts = db.query(APIDriftEvent).all()
    print(f"\nTotal Drift Events in DB: {len(drifts)}")
    for d in drifts:
        print(f"  -> Drift: API='{d.api_name}', Type='{d.change_type}', Path='{d.path}', Method='{d.method}', Ack={d.acknowledged}")
