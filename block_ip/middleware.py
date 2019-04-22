from django.http import HttpResponseForbidden
from django.conf import settings
from django.core.cache import cache

from .models import BlockIP


def get_ip(req):
    return req.META.get('HTTP_X_REAL_IP') or req.META['REMOTE_ADDR']


def is_ip_in_nets(ip, nets):
    for net in nets:
        return ip in net
    return False


class BlockIPMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        is_banned = False

        ip = get_ip(request)
        # TODO: Look into something more optimized for large numbers
        # of blocks. https://github.com/jimfunk/django-postgresql-netfields
        block_ips = cache.get('blockip:list')
        if block_ips is None:
            block_ips = BlockIP.objects.all()
            cache.set('blockip:list', block_ips)
        deny_ips = [i.get_network() for i in block_ips]

        for net in deny_ips:
            if ip in net:
                is_banned = True
                break

        if is_banned:
            # delete sessions when denied
            for k in request.session.keys():
                del request.session[k]
            return HttpResponseForbidden("")
        return self.get_response(request)
