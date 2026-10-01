import json
from typing import Dict, Any, List, Tuple
from sqlalchemy import func
from database.database import get_db
from database.models import API, APIEndpoint, APIDriftEvent, APIDependency

class APIDiscoveryManager:
    """Manages endpoint discovery, database persistence, drift detection, and dependencies."""

    @classmethod
    def save_api_and_endpoints(
        cls,
        user_id: str,
        spec_data: Dict[str, Any],
        raw_spec: str,
        source_type: str,
        environment: str = 'Production',
        owner: str = None,
        custom_name: str = None,
        custom_base_url: str = None
    ) -> Tuple[API, List[APIDriftEvent]]:
        db = get_db()
        api_name = custom_name.strip() if custom_name else spec_data.get('title', 'API Service')
        base_url = custom_base_url.strip() if custom_base_url else spec_data.get('base_url', 'https://api.example.com')
        
        # Check if API with same name already exists in same environment -> Drift Detection!
        existing_api = db.query(API).filter(
            func.lower(API.name) == api_name.lower(),
            func.lower(API.environment) == environment.lower()
        ).first()
        
        # If not found by exact environment, match by name to support updating existing service baseline
        if not existing_api:
            existing_api = db.query(API).filter(
                func.lower(API.name) == api_name.lower()
            ).first()
            
        drift_events = []
        
        if existing_api:
            # We are updating an existing API -> Run Drift Detection!
            api_obj = existing_api
            api_obj.version = spec_data.get('version', api_obj.version)
            api_obj.base_url = base_url
            api_obj.source_type = source_type
            api_obj.raw_spec = raw_spec
            api_obj.environment = environment
            if owner:
                api_obj.owner = owner
                
            drift_events = cls.detect_drift(api_obj, spec_data.get('endpoints', []))
            
            # Clear old endpoints and dependencies to recreate fresh inventory
            for ep in api_obj.endpoints:
                db.delete(ep)
            for dep in api_obj.dependencies:
                db.delete(dep)
        else:
            api_obj = API(
                user_id=user_id,
                name=api_name,
                version=spec_data.get('version', '1.0.0'),
                base_url=base_url,
                source_type=source_type,
                raw_spec=raw_spec,
                owner=owner or 'Security Team',
                environment=environment,
                status='Active',
                description=spec_data.get('description', '')
            )
            db.add(api_obj)
            db.flush()

        # Add endpoints
        for ep_data in spec_data.get('endpoints', []):
            endpoint = APIEndpoint(
                api_id=api_obj.id,
                method=ep_data.get('method', 'GET'),
                path=ep_data.get('path', '/'),
                summary=ep_data.get('summary', ''),
                description=ep_data.get('description', ''),
                parameters_json=json.dumps(ep_data.get('parameters', [])),
                request_body_json=json.dumps(ep_data.get('request_body', {})),
                response_schemas_json=json.dumps(ep_data.get('response_schemas', {})),
                auth_required=ep_data.get('auth_required', False),
                auth_types_json=json.dumps(ep_data.get('auth_types', [])),
                tags_json=json.dumps(ep_data.get('tags', [])),
                risk_status='UNTESTED'
            )
            db.add(endpoint)

        # Add dependencies
        for dep_data in spec_data.get('dependencies', []):
            dependency = APIDependency(
                api_id=api_obj.id,
                service_name=dep_data.get('service_name', 'External Service'),
                target_url=dep_data.get('target_url', ''),
                dependency_type=dep_data.get('dependency_type', 'EXTERNAL_API'),
                description=dep_data.get('description', '')
            )
            db.add(dependency)

        # Save any drift events
        for drift in drift_events:
            db.add(drift)

        db.commit()
        return api_obj, drift_events

    @classmethod
    def detect_drift(cls, api_obj: API, new_endpoints: List[Dict[str, Any]]) -> List[APIDriftEvent]:
        """Detect drift between existing endpoints and newly uploaded spec."""
        drift_events = []
        old_map = {(ep.method.upper(), ep.path): ep for ep in api_obj.endpoints}
        new_map = {(ep['method'].upper(), ep['path']): ep for ep in new_endpoints}

        # 1. New endpoints added
        for key, ep in new_map.items():
            if key not in old_map:
                drift = APIDriftEvent(
                    api_id=api_obj.id,
                    change_type='ENDPOINT_ADDED',
                    change_scope='ENDPOINT',
                    path=ep['path'],
                    method=ep['method'],
                    old_value=None,
                    new_value=f"New endpoint added: {ep['method']} {ep['path']}"
                )
                drift_events.append(drift)

        # 2. Endpoints removed
        for key, ep in old_map.items():
            if key not in new_map:
                drift = APIDriftEvent(
                    api_id=api_obj.id,
                    change_type='ENDPOINT_REMOVED',
                    change_scope='ENDPOINT',
                    path=ep.path,
                    method=ep.method,
                    old_value=f"Endpoint existed: {ep.method} {ep.path}",
                    new_value=None
                )
                drift_events.append(drift)

        # 3. Changes in existing endpoints (auth or params)
        for key in old_map.keys() & new_map.keys():
            old_ep = old_map[key]
            new_ep = new_map[key]

            if old_ep.auth_required != new_ep.get('auth_required', False):
                drift = APIDriftEvent(
                    api_id=api_obj.id,
                    change_type='AUTH_CHANGED',
                    change_scope='AUTH',
                    path=old_ep.path,
                    method=old_ep.method,
                    old_value=f"Auth Required: {old_ep.auth_required}",
                    new_value=f"Auth Required: {new_ep.get('auth_required', False)}"
                )
                drift_events.append(drift)

        return drift_events
