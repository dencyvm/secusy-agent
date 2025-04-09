# routing.py
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path
from .consumers import DataConsumer

application = ProtocolTypeRouter({
    'websocket': URLRouter([
        path('ws/data/', DataConsumer.as_asgi()),
    ]),
})


