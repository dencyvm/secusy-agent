# consumers.py
import json
import asyncio
import requests
from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import urlparse
from django.utils import timezone
from django.conf import settings
from scannerWebSocket.token_utils import create_token



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
                    reference_scan_id = scan['reference_scan_id']
                    scan_action = scan['action']
                    url = agent_end_point.strip("/")

                    if scan_action == 'start':
                        scanner_endpoint = url + "/scan"
                    elif scan_action == 'pause':
                        url_part = f"/scan/{reference_scan_id}/pause/"
                        scanner_endpoint = url + url_part
                    elif scan_action == 'resume':
                        url_part = f"/scan/{reference_scan_id}/resume/"
                        scanner_endpoint = url + url_part
                    elif scan_action == 'stop':
                        url_part = f"/scan/{reference_scan_id}/stop/"
                        scanner_endpoint = url + url_part
                    else:
                        scanner_endpoint = url + "/scan"

                    scanner_response_data = {}
                    scanner_response_data['scan_id'] = scan['scan_id']
                    scanner_response_data['scan_type'] = scan['scan_type']
                    scanner_response_data['action'] = scan_action

                    if scan_action == 'start':
                        payload = {}
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
                                "scan_type": "network_scan",
                                "scan_input_meta": scan['scan_input_meta']
                            }
                        if agent_type == "zap":
                            payload = {
                                "target": scan['target'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan",
                                "postman_file": scan['file_path'],
                                "scan_input_meta": scan['scan_input_meta']
                            }
                        if agent_type == "ssllabs":
                            payload = {
                                "target": scan['target'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
                            }
                        if agent_type == "dsscan":
                            parsed_url = urlparse(scan['target'])
                            if parsed_url.netloc == '':
                                main_domain = parsed_url.path.split(".")[-2] + "." + parsed_url.path.split(".")[-1]
                            else:
                                main_domain = parsed_url.netloc.split(".")[-2] + "." + parsed_url.netloc.split(".")[-1]
                            payload = {
                                "domain": main_domain,
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
                            }
                        if agent_type == "ipreputation":
                            pass
                        if agent_type == "wpscan":
                            payload = {
                                "target": scan['target'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
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
                                "ip_string": scan['target'],
                                "ports_string": agent_meta['ports_string'],
                                "scan_scope": scan['scan_scope'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
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
                                "ip_string": scan['target'],
                                "ports_string": agent_meta['ports_string'],
                                "scan_scope": scan['scan_scope'],
                                "org_ref_id": settings.ORG_ID,
                                "scan_type": "network_scan"
                            }
                            
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
                    else:
                        try:
                            response = requests.post(scanner_endpoint, timeout=10)
                            if result is not None:
                                json_response = response.json()

                                if json_response.get('status') == 'success':
                                    if scan_action == 'pause':
                                        scanner_response_data['scan_status'] = 7
                                    elif scan_action == 'resume':
                                        scanner_response_data['scan_status'] = 9 # passing 9 for handling inprogress(1) status, 
                                    elif scan_action == 'stop':
                                        scanner_response_data['scan_status'] = 8
                                    else:
                                        pass
                        except Exception as e:
                            print(f"Scan action error: {str(e)}.")
                    
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
