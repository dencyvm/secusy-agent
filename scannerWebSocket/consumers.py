# consumers.py
import json
import asyncio
import requests
from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import urlparse
from django.utils import timezone
from django.conf import settings
from scannerWebSocket.token_utils import create_token
import base64
from cryptography.fernet import Fernet


def decrypt(string):
    try:
        # base64 decode
        txt = base64.urlsafe_b64decode(string)
        cipher_suite = Fernet(settings.ENCRYPT_KEY)
        decoded_text = cipher_suite.decrypt(txt).decode("ascii")     
        return decoded_text
    except Exception as e:
        # log the error
        print(e)
        return None


class DataConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        # Start the periodic task when the WebSocket connection is established
        asyncio.ensure_future(self.periodic_task())

    async def fetch_prescheduled_scans_and_update_scan_response(self):
        # Fetch data from API of core-application
        try:
            print(">>> Fetch prescheduled scan data <<<")
            # Create a token
            token = create_token(settings.ORG_ID)
            headers = {
                'org-id': settings.ORG_ID,
                'X-Service-Token': token
            }
            params = {
                'network':settings.NETWORK_LOCATION
            }
            preschedule_endpoint = settings.SECUSY_API + '/scan/prescheduled-scans'
            response = requests.get(
                preschedule_endpoint,
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                pre_scheduled_scans = response.json()
                # Create internal scan using response data
                for scan in pre_scheduled_scans:
                    agent_type = scan['agent_type']['agent_type_code']
                    agent_end_point = scan['agent_id']['agent_end_point']
                    url = agent_end_point.strip("/")
                    scanner_endpoint = url + "/scan"
                    payload = {}

                    if scan['scan_type'] == 'asset_scan':
                        if agent_type == "nessus":
                            if scan['nessus_policy'] != None:
                                policy_type = scan['nessus_policy']['policy_name']
                                policy_file = scan['nessus_policy']['policy_file']
                            else:
                                policy_type = None
                                policy_file = None
                            payload = {
                                "target": scan['asset_id']['asset_name'],
                                "policy_type": policy_type,
                                "policy_file": policy_file,
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "burpsuit":
                            asset_url_id = scan['url_id']
                            asset_url = asset_url_id['url'] if asset_url_id is not None else scan['asset_id']['asset_name']
                            payload = {
                                "urls": asset_url,
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "masscan":
                            if scan['schedule'] != None and scan['schedule']['scan_input_meta'] is not None:
                                agent_meta = json.loads(scan['schedule']['scan_input_meta'])
                            else:
                                if scan['scan_input_meta'] is not None:
                                    agent_meta = json.loads(scan['scan_input_meta'])
                                else:
                                    agent_meta = json.loads(scan['agent_id']['agent_meta'])
                            payload = {
                                "ip_string": scan['asset_id']['asset_name'],
                                "ports_string": agent_meta['ports_string'],  # Load it from meta
                                "scan_scope": scan['scan_scope'],
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "attack_surface":
                            if scan['schedule'] != None and scan['schedule']['scan_input_meta'] is not None:
                                agent_meta = json.loads(scan['schedule']['scan_input_meta'])
                            else:
                                if scan['scan_input_meta'] is not None:
                                    agent_meta = json.loads(scan['scan_input_meta'])
                                else:
                                    agent_meta = json.loads(scan['agent_id']['agent_meta'])
                            payload = {
                                "ip_string": scan['asset_id']['asset_name'],
                                "ports_string": agent_meta['ports_string'],  # Load it from meta
                                "scan_scope": scan['scan_scope'],
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "wpscan":
                            asset_url_id = scan['url_id']
                            asset_url = asset_url_id['url'] if asset_url_id is not None else scan['asset_id']['asset_name']
                            payload = {
                                "target": asset_url,
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "dsscan":
                            parsed_url = urlparse(scan['asset_id']['asset_name'])
                            if parsed_url.netloc == '':
                                main_domain = parsed_url.path.split(".")[-2] + "." + parsed_url.path.split(".")[-1]
                            else:
                                main_domain = parsed_url.netloc.split(".")[-2] + "." + parsed_url.netloc.split(".")[-1]
                            payload = {
                                "domain": main_domain,
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "ipreputation":
                            pass
                        if agent_type == "ssllabs":
                            payload = {
                                "target": scan['asset_id']['asset_name'],
                                "org_ref_id": settings.ORG_ID
                            }
                        if agent_type == "zap":
                            asset_url_id = scan['url_id']
                            asset_url = asset_url_id['url'] if asset_url_id is not None else scan['asset_id']['asset_name']
                            payload = {
                                "target": asset_url,
                                "org_ref_id": settings.ORG_ID
                            }
                    else:
                        if agent_type == "nessus":
                            if scan['nessus_policy'] != None:
                                policy_type = scan['nessus_policy']['policy_name']
                                policy_file = scan['nessus_policy']['policy_file']
                            else:
                                policy_type = None
                                policy_file = None

                            payload = {
                                "target": scan['target'],
                                "policy_type": policy_type,
                                "policy_file": policy_file,
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
                            }
                        if agent_type == "burpsuit":
                            target = scan['target']
                            payload = {
                                "urls": target,
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
                            }
                        if agent_type == "zap":
                            scan_input_meta = json.loads(scan['scan_input_meta'])
                            username = scan_input_meta.get("username")
                            password = decrypt(scan_input_meta.get("password"))

                            payload = {
                                "target": scan['target'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan",
                                "postman_file": scan['file_path'],
                                "username": username,
                                "password": password
                            }
                    
                    scanner_response_data = {}
                    scanner_response_data['scan_id'] = scan['scan_id']
                    scanner_response_data['scan_type'] = scan['scan_type']
                    try:
                        result = requests.post(scanner_endpoint, json=payload, timeout=15)
                        if result is not None:
                            scan_result = result.json()

                            # Create scan data to update secusy
                            scanner_response_data['result_file'] = scan_result['result_url']
                            scanner_response_data['errors'] = scan_result['errors']
                            scanner_response_data['reference_scan_id'] = scan_result['scan_id']
                            scanner_response_data['scan_result_meta'] = scan_result
                            scanner_response_data['last_run_at'] = timezone.now().isoformat()
                            scanner_response_data['scan_status'] = 1
                    except Exception as e:
                        scanner_response_data['last_run_at'] = timezone.now().isoformat()
                        scanner_response_data['errors'] = "Scanner down. "+str(e)
                        scanner_response_data['is_scan_paused'] = True
                        scanner_response_data['scan_status'] = 3

                    # return internal scanner response to secusy
                    try:
                        scan_endpoint = settings.SECUSY_API + '/scan/prescheduled-scan-update/'
                        res = requests.post(
                            scan_endpoint,
                            headers=headers,
                            json=scanner_response_data, 
                            timeout=15
                        )
                    except Exception as e:
                        print(">>> scan response update api error: ",str(e))

            print(">>> prescheduled scan completed <<<") 
        except Exception as e:
            print(">>> secusy api error: ",str(e))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        # Receive data from the client
        data = json.loads(text_data)
        print(f"Received request from client: {data}")

        # Send back the processed data to the client
        processed_data = {'response': 'Request received.'}
        try:
            await self.send(text_data=json.dumps({
                'type': 'response',
                'data': processed_data,
            }))
        except Exception as e:
            print(f"Error sending message: {e}")

    async def periodic_task(self):
        while True:
            # await asyncio.sleep(300)  # Sleep for 5 minutes
            await self.fetch_prescheduled_scans_and_update_scan_response()
            await asyncio.sleep(300)  # Sleep for 5 minutes
