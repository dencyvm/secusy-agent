
import asyncio
import websockets
import json

async def connect_to_websocket():
    print("Trying async via WS")
    async with websockets.connect('ws://web:8099/ws/data/') as websocket:
        # Send a message to the server
        message_to_send = {'message': 'Internal agent!'}
        await websocket.send(json.dumps(message_to_send))
        print(f"Sent message: {message_to_send}")

        # Receive a message from the server
        response = await websocket.recv()
        try:
            data = json.loads(response)
            print(f"Received message from server: {data}")
        except json.JSONDecodeError as json_error:
            print(f"Error decoding JSON: {json_error}")

# Run the WebSocket connection
asyncio.get_event_loop().run_until_complete(connect_to_websocket())
