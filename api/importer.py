import hashlib
import json
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime

class OpenAPIImporter:
    """Parses and validates OpenAPI 3.x and Swagger 2.0 specifications."""

    @staticmethod
    def calculate_spec_hash(raw_spec: str) -> str:
        return hashlib.sha256(raw_spec.encode('utf-8')).hexdigest()

    @classmethod
    def validate_and_extract(cls, spec_dict: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Validate structure and extract comprehensive metadata & endpoint inventory."""
        if not isinstance(spec_dict, dict):
            return None, "Specification must be a JSON/YAML object."

        # Detect version
        openapi_ver = spec_dict.get('openapi')
        swagger_ver = spec_dict.get('swagger')
        
        if not openapi_ver and not swagger_ver:
            return None, "Invalid API specification: Missing 'openapi' or 'swagger' version tag."

        is_oas3 = bool(openapi_ver and str(openapi_ver).startswith('3.'))
        is_swagger2 = bool(swagger_ver and str(swagger_ver).startswith('2.'))

        if not (is_oas3 or is_swagger2):
            return None, f"Unsupported specification format (Found openapi: '{openapi_ver}', swagger: '{swagger_ver}'). Expected OpenAPI 3.x or Swagger 2.0."

        info = spec_dict.get('info', {})
        api_title = info.get('title', 'Untitled API').strip()
        api_version = info.get('version', '1.0.0').strip()
        api_description = info.get('description', '').strip()

        # Extract Base URL
        base_url = "https://api.example.com"
        if is_oas3:
            servers = spec_dict.get('servers', [])
            if servers and isinstance(servers, list) and len(servers) > 0:
                first_server = servers[0]
                if isinstance(first_server, dict):
                    base_url = first_server.get('url', 'https://api.example.com')
        elif is_swagger2:
            host = spec_dict.get('host', 'api.example.com')
            base_path = spec_dict.get('basePath', '')
            schemes = spec_dict.get('schemes', ['https'])
            scheme = schemes[0] if schemes else 'https'
            base_url = f"{scheme}://{host}{base_path}"

        # Extract Security Schemes
        security_schemes = {}
        if is_oas3:
            components = spec_dict.get('components', {})
            security_schemes = components.get('securitySchemes', {})
        elif is_swagger2:
            security_schemes = spec_dict.get('securityDefinitions', {})

        global_security = spec_dict.get('security', [])

        # Extract Paths and Endpoints
        paths_obj = spec_dict.get('paths', {})
        if not isinstance(paths_obj, dict):
            return None, "Invalid 'paths' definition in specification."

        endpoints = []
        method_counts = {'GET': 0, 'POST': 0, 'PUT': 0, 'DELETE': 0, 'PATCH': 0, 'OPTIONS': 0, 'HEAD': 0, 'OTHER': 0}
        dependencies = []

        # Check for external docs or callbacks that indicate external dependencies
        if 'externalDocs' in spec_dict and isinstance(spec_dict['externalDocs'], dict):
            doc_url = spec_dict['externalDocs'].get('url')
            if doc_url:
                dependencies.append({
                    'service_name': 'External Documentation Portal',
                    'target_url': doc_url,
                    'dependency_type': 'EXTERNAL_API',
                    'description': spec_dict['externalDocs'].get('description', 'Documentation service')
                })

        for path, path_item in paths_obj.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get('parameters', [])

            for method_key in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
                if method_key not in path_item:
                    continue

                op = path_item[method_key]
                if not isinstance(op, dict):
                    continue

                method_upper = method_key.upper()
                if method_upper in method_counts:
                    method_counts[method_upper] += 1
                else:
                    method_counts['OTHER'] += 1

                summary = op.get('summary', '')
                description = op.get('description', '')
                tags = op.get('tags', [])
                if not isinstance(tags, list):
                    tags = []

                # Combine path-level and operation-level parameters
                op_params = op.get('parameters', [])
                all_params = []
                if isinstance(path_level_params, list):
                    all_params.extend(path_level_params)
                if isinstance(op_params, list):
                    all_params.extend(op_params)

                cleaned_params = []
                for p in all_params:
                    if isinstance(p, dict):
                        cleaned_params.append({
                            'name': p.get('name', 'unnamed'),
                            'in': p.get('in', 'query'),
                            'required': p.get('required', False),
                            'type': p.get('schema', {}).get('type') if 'schema' in p else p.get('type', 'string'),
                            'description': p.get('description', '')
                        })

                # Request Body
                request_body = {}
                if is_oas3:
                    rb = op.get('requestBody', {})
                    if isinstance(rb, dict):
                        content = rb.get('content', {})
                        request_body = {
                            'required': rb.get('required', False),
                            'content_types': list(content.keys()),
                            'description': rb.get('description', '')
                        }
                elif is_swagger2:
                    # Swagger 2 uses in: body parameter
                    body_param = next((p for p in all_params if isinstance(p, dict) and p.get('in') == 'body'), None)
                    if body_param:
                        request_body = {
                            'required': body_param.get('required', False),
                            'content_types': ['application/json'],
                            'description': body_param.get('description', '')
                        }

                # Responses
                responses = op.get('responses', {})
                response_schemas = {}
                if isinstance(responses, dict):
                    for status_code, resp_obj in responses.items():
                        if isinstance(resp_obj, dict):
                            response_schemas[str(status_code)] = {
                                'description': resp_obj.get('description', '')
                            }

                # Authentication requirement
                op_security = op.get('security', global_security)
                auth_required = bool(op_security and len(op_security) > 0)
                auth_types = []
                if auth_required:
                    for sec_req in op_security:
                        if isinstance(sec_req, dict):
                            for sec_name in sec_req.keys():
                                scheme_def = security_schemes.get(sec_name, {})
                                stype = scheme_def.get('type', sec_name)
                                if stype not in auth_types:
                                    auth_types.append(stype)

                endpoints.append({
                    'method': method_upper,
                    'path': path,
                    'summary': summary,
                    'description': description,
                    'parameters': cleaned_params,
                    'request_body': request_body,
                    'response_schemas': response_schemas,
                    'auth_required': auth_required,
                    'auth_types': auth_types,
                    'tags': tags,
                    'risk_status': 'UNTESTED'
                })

        extracted_data = {
            'spec_version': openapi_ver or swagger_ver,
            'spec_format': 'OpenAPI 3.x' if is_oas3 else 'Swagger 2.0',
            'title': api_title,
            'version': api_version,
            'description': api_description,
            'base_url': base_url,
            'security_schemes': list(security_schemes.keys()),
            'global_security': bool(global_security),
            'total_endpoints': len(endpoints),
            'method_counts': method_counts,
            'endpoints': endpoints,
            'dependencies': dependencies
        }

        return extracted_data, None
