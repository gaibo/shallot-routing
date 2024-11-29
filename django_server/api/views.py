from datetime import timedelta
from typing import Final

from django.core.exceptions import BadRequest
from django.forms import ModelForm
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from ipware import get_client_ip

from .models import Node

NODE_TIMEOUT: Final[int] = 60 # timeout in seconds

class NodeForm(ModelForm):
    """
    ModelForm for Node model.
    """
    class Meta:
        model = Node
        fields = ['name', 'port', 'pubkey']

def register(request):
    """
    Register a new node to the list. Only accepts POST requests.
    """
    if request.method != 'POST':
        raise BadRequest()
    form = NodeForm(request.POST)
    if form.is_valid():
        # If name already exists, replace
        Node.objects.filter(name=form.cleaned_data['name']).delete()
        node = form.save(commit=False)
        ip, is_routable = get_client_ip(request)
        if ip is None or not is_routable:
            raise BadRequest()
        node.ip = ip
        node.save()
        return HttpResponse('OK')
    else:
        raise BadRequest()

def list_nodes(request):
    """
    Return a list of all nodes currently registered.
    """
    # Remove stale nodes
    Node.objects.filter(timestamp__lte=timezone.now() - timedelta(seconds=NODE_TIMEOUT)).delete()
    # Map nodes to a nice JSON dict without useless info
    return JsonResponse({n['name']: {k: n[k] for k in ['ip', 'port', 'pubkey']} for n in list(Node.objects.values())})
