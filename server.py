from aiohttp import web
import asyncio
from bleak import BleakScanner
from bleak import BleakClient
import json
import time
import functools
import hashlib
import RPi.GPIO as GPIO
import os
import ctypes
import copy
import base64

class Chars(ctypes.Structure):
    _fields_ = [('data', ctypes.POINTER(ctypes.c_ubyte)), ("size", ctypes.c_ulong)]

rsa = ctypes.cdll.LoadLibrary("./librsa.so")

rsa.generate.restype = None
rsa.generate.argtypes = []

rsa.get_pk.restype = Chars
rsa.get_pk.argtypes = []

rsa.get_sk.restype = Chars
rsa.get_sk.argtypes = []

rsa.encrypt.restype = Chars
rsa.encrypt.argtypes = [ Chars, Chars ]

rsa.decrypt.restype = Chars
rsa.decrypt.argtypes = [ Chars, Chars ]

rsa_pk = None
rsa_sk = None

def rsa_generate():
    rsa.generate()

def rsa_get():
    global rsa_pk
    global rsa_sk
    pk_chars = rsa.get_pk()
    sk_chars = rsa.get_sk()
    rsa_pk = ctypes.string_at(pk_chars.data, pk_chars.size).decode('utf8')
    rsa_sk = ctypes.string_at(sk_chars.data, sk_chars.size).decode('utf8')
    rsa.free_chars(pk_chars)
    rsa.free_chars(sk_chars)
    
def rsa_encrypt(pk, plainText):
    pk = pk.encode('utf8')
    plainText = plainText.encode('utf8')

    pk_chars = Chars()
    pk_chars.data = (ctypes.c_ubyte * len(pk)).from_buffer(bytearray(pk))
    pk_chars.size = len(pk)

    plainText_chars = Chars()
    plainText_chars.data = (ctypes.c_ubyte * len(plainText)).from_buffer(bytearray(plainText))
    plainText_chars.size = len(plainText)

    cipherText_chars = rsa.encrypt(pk_chars, plainText_chars)
    ret = ctypes.string_at(cipherText_chars.data, cipherText_chars.size)
    rsa.free_chars(cipherText_chars)
    
    return base64.b64encode(ret).decode('utf8')

def rsa_decrypt(sk, cipherText):
    sk = sk.encode('utf8')
    cipherText = base64.b64decode(cipherText)

    sk_chars = Chars()
    sk_chars.data = (ctypes.c_ubyte * len(sk)).from_buffer(bytearray(sk))
    sk_chars.size = len(sk)

    cipherText_chars = Chars()
    cipherText_chars.data = (ctypes.c_ubyte * len(cipherText)).from_buffer(bytearray(cipherText))
    cipherText_chars.size = len(cipherText)

    plainText_chars = rsa.decrypt(sk_chars, cipherText_chars)
    ret = ctypes.string_at(plainText_chars.data, plainText_chars.size)
    rsa.free_chars(plainText_chars)
    return ret.decode('utf8')

def encode(pk_uid, data, bSecurity):
    global whites
    try:
        ret = json.dumps(data)
        if bSecurity:
            ret = rsa_encrypt(whites[pk_uid]['pk'], ret)
    except BaseException as e:
        print('encode', e)
        raise web.HTTPForbidden()
    return ret

def decode(data, bSecurity):
    global rsa_sk
    try:
        ret = data
        if bSecurity:
            ret = rsa_decrypt(rsa_sk, data)
        ret = json.loads(ret)
    except BaseException as e:
        print('decode', e)
        raise web.HTTPForbidden()
    return ret

routes = web.RouteTableDef()
clients = []
configs = {}
scan_then_connect_state = 'idling'
scan_then_connect_count = 0
scan_then_connect_latest = ""
count = 0
views = {}
autos = {}
tasks = {}
unsafe = False
unsafe_count = 0
unsafe_guard = 0
whites = {}
threshold = 2

def unsafe_update_and_notify(value):
    global unsafe_count
    global unsafe_guard
    global unsafe
    unsafe = value
    if unsafe:
        GPIO.output(18, GPIO.HIGH)
        unsafe_guard = 0
    else:
        GPIO.output(18, GPIO.LOW)
        unsafe_count = 0

async def state_update_and_notify(address, state):
    global configs
    configs[address]['state'] = state
    for auto in autos.values():
        if 'state' not in auto:
            continue
        if auto['state']['address'] != address:
            continue
        if auto['state']['state'] == state:
            await apply_view(auto['view'])

def get_client(address):
    global clients
    for client in clients:
        if client.address == address:
            return client
    return None

async def download_config(client):
    global configs
    value = await client.read_gatt_char('01010101-0101-0101-0101-010101010102')
    if client.address not in configs:
        configs[client.address] = {}
    configs[client.address]['type'] = value[0]
    await state_update_and_notify(client.address, value[1])
    configs[client.address]['address'] = client.address
    configs[client.address]['connected'] = True

async def upload_state(client, state):
    await client.write_gatt_char('01010101-0101-0101-0101-010101010102', state.to_bytes(1, 'little'))

def filterfunc(bd, ad): 
    return '01010101-0101-0101-0101-010101010101' in ad.service_uuids

def disconnected_callback(client):
    global clients
    if client in clients and not client.is_connected:
        clients.remove(client)
        configs[client.address]["connected"] = False

async def notify_callback(client, sender, value):
    global configs
    config = configs[client.address]
    config['type'] = value[0]
    await state_update_and_notify(client.address, value[1])
    
async def scan_then_connect():
    global scan_then_connect_state
    global scan_then_connect_count
    global scan_then_connect_latest
    global clients
    if scan_then_connect_state != 'idling':
        return
    scan_then_connect_latest = ""
    scan_then_connect_state = 'scanning'
    bd = await BleakScanner.find_device_by_filter(filterfunc)
    if bd != None:
        client = BleakClient(bd.address, disconnected_callback)
        scan_then_connect_state = "connecting"
        await client.connect()
        if client.is_connected:
            clients.append(client)
            await download_config(client)
            await client.start_notify("01010101-0101-0101-0101-010101010102", functools.partial(notify_callback, client))
            scan_then_connect_latest = client.address
    scan_then_connect_count += 1
    scan_then_connect_state = 'idling'

def get_uid():
    global count
    count += 1
    return count

async def apply_view(uid):
    view = views[uid]
    for state in view['states']:
        await upload_state(get_client(state['address']), state['state'])

async def handle_auto(auto):
    while True:
        offset = auto['start'] - int(time.time())
        if offset > 0:
            await asyncio.sleep(offset)
        await apply_view(auto['view'])
        if 'every' not in auto:
            break
        auto['start'] += auto['every']

def done_callback(uid, task):
    global autos
    global tasks
    if uid in autos:
        autos.pop(uid)
    if uid in tasks:
        tasks.pop(uid)

def get_hash():
    global configs
    global views
    global autos
    global whites
    global unsafe
    related_configs = []
    for k, v in configs.items():
        related_config = {}
        related_config['address'] = k
        related_config['connected'] = v['connected']
        related_config['state'] = v['state']
        related_config['type'] = v['type']
        related_configs.append(related_config)
    related_configs.sort(key=lambda a: a['address'])
    view_uids = list(views.keys())
    view_uids.sort()
    auto_uids = list(autos.keys())
    auto_uids.sort()
    white_uids = list(whites.keys())
    white_uids.sort()
    str = json.dumps([ related_configs, view_uids, auto_uids, white_uids, unsafe ]).replace(' ', '')
    hl = hashlib.md5()
    hl.update(str.encode('utf-8'))
    hashed = hl.hexdigest()
    return hashed

def check_hash(args):
    if 'hash' in args and args['hash'] != get_hash():
        raise web.HTTPPreconditionFailed()

def get_bSecurity(request):
    return not (request.host.startswith('localhost') or request.host.startswith('127.0.0.1'))

@routes.post('/ping')
async def _ping(request):
    global unsafe
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['hash'] = get_hash()
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/peek')
async def _peek(request):
    global unsafe
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['state'] = scan_then_connect_state
    content['count'] = scan_then_connect_count
    content['latest'] = scan_then_connect_latest
    content['unsafe'] = unsafe
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/discover')
async def _discover(request):
    ret = await _peek(request)
    asyncio.create_task(scan_then_connect())
    return ret

@routes.post('/disconnect')
async def _disconnect(request):
    content = {}
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    client = get_client(args['address'])
    if client == None:
        raise web.HTTPNotFound()
    affected = 0
    if await client.disconnect():
        affected += 1
    content["affected"] = affected
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/config')
async def _config(request):
    global configs
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = args
    address = content['address']
    if address not in configs:
        raise web.HTTPNotFound()
    if len(content) > threshold:
        config = configs[address]
        content['type'] = config['type']
        content['state'] = config['state']
        content['connected'] = get_client(address) != None
        configs[address] = content
    else:
        content = configs[address]
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/configs')
async def _configs(request):
    global configs
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['addresses'] = list(configs.keys())
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/state')
async def _state(request):
    global configs
    content = {}
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    address = args['address']
    client = get_client(address)
    if client == None:
        raise web.HTTPNotFound()
    if 'state' in args:
        check_hash(args)
        await upload_state(client, args['state'])
    value = await client.read_gatt_char('01010101-0101-0101-0101-010101010102')
    content['state'] = value[1]
    config = configs[address]
    config['type'] = value[0]
    await state_update_and_notify(address, value[1])
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/filter')
async def _filter(request):
    global configs
    content = {}
    content['addresses'] = []
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    for address, config in configs.items():
        mark = True
        for k, v in args.items():
            if k not in config or v != config[k]:
                mark = False
                break
        if mark:
            content['addresses'].append(address)
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/view')
async def _view(request):
    global views
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = args
    if 'uid' in content:
        uid = content['uid']
        if uid not in views:
            raise web.HTTPNotFound()
        view = views[uid]
        if len(content) > threshold:
            content['states'] = view['states']
            views[uid] = content
        else:
            content = view
    else:
        uid = get_uid()
        content['uid'] = uid
        views[uid] = content
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/views')
async def _views(request):
    global views
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['uids'] = list(views.keys())
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/auto')
async def _auto(request):
    global autos
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = args
    if 'uid' in content:
        uid = content['uid']
        if uid not in autos:
            raise web.HTTPNotFound()
        content = autos[uid]
    else:
        check_hash(content)
        uid = get_uid()
        content['uid'] = uid
        autos[uid] = content
        if 'state' not in content:
            if 'start' not in content:
                content['start'] = int(time.time())
            task = asyncio.create_task(handle_auto(content))
            task.add_done_callback(functools.partial(done_callback, uid))
            tasks[uid] = task
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/autos')
async def _autos(request):
    global autos
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['uids'] = list(autos.keys())
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/abort')
async def _abort(request):
    global views
    global tasks
    global configs
    content = {}
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    affected = 0
    if 'uid' in args:
        uid = args['uid']
        if uid in views:
            views.pop(uid)
            affected += 1
        if uid in tasks:
            tasks[uid].cancel()
            affected += 1
        elif uid in autos:
            autos.pop(uid)
            affected += 1
    if 'address' in args:
        address = args['address']
        if address in configs:
            client = get_client(address)
            if client != None:
                await client.disconnect()
            configs.pop(address)
            affected += 1
    content['affected'] = affected
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/white')
async def _white(request):
    global whites
    global unsafe
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = args
    pk_uid = args['pk_uid']
    if 'uid' in content:
        uid = content['uid']
        if uid not in whites:
            raise web.HTTPNotFound()
        content = copy.deepcopy(whites[uid])
        content.pop('pk')
    else:
        if not unsafe:
            raise web.HTTPForbidden()
        pk_uid = get_uid()
        content['uid'] = pk_uid
        content['time'] = int(time.time())
        whites[pk_uid] = content
        unsafe_update_and_notify(False)
    return web.Response(body=encode(pk_uid, content, bSecurity))

@routes.post('/unwhite')
async def _unwhite(request):
    global whites
    global unsafe
    if not unsafe:
        raise web.HTTPForbidden()
    content = {}
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    affected = 0
    uid = args['uid']
    if uid in whites:
        affected += 1
        whites.pop(uid)
    content['affected'] = affected
    unsafe_update_and_notify(False)
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

@routes.post('/whites')
async def _whites(request):
    global whites
    bSecurity = get_bSecurity(request)
    args = decode(await request.content.read(), bSecurity)
    content = {}
    content['uids'] = list(whites.keys())
    return web.Response(body=encode(args['pk_uid'], content, bSecurity))

async def on_shutdown(app):
    global clients
    while clients:
        await clients[0].disconnect()

async def unsafe_mode():
    global unsafe
    global unsafe_count
    global unsafe_guard
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(17, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(18, GPIO.OUT)
    GPIO.output(18, GPIO.LOW)
    before = True
    current = True
    while True:
        before = current
        current = GPIO.input(17)
        if unsafe:
            unsafe_guard += 1
            if (before == True and current == False) or unsafe_guard > 30:
                unsafe_update_and_notify(False)
        else:
            if current == False:
                unsafe_count += 1
            if unsafe_count > 3:
                unsafe_update_and_notify(True)
        await asyncio.sleep(1)

async def on_startup(app):
    asyncio.create_task(unsafe_mode())

app = web.Application()
app.on_shutdown.append(on_shutdown)
app.on_startup.append(on_startup)
app.add_routes(routes)

if __name__ == '__main__':
    rsa_generate()
    rsa_get()
    plainText = '{"pk":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyEefkgD+rnrI22x42bD\nKOO1RJKIj3YZTLWAUR2N/1TAx8IH+gMEG/97HKTxspXOElBQuALfVPpJN4LesVfi\nTiJHHtzcqoD6LXJn7Jg0dk5LskvcnVzWtc0ZZqMiV9W6HtmtnGhEfLT5M6PIA23e\nukmwhsv+Kg04lCPej8kSKnMs7ftUxSIXV9eTsH5cZL98OiHj9FJ/w1gPedOmAdnz\na43PvlowZnTJU8rtL204MSDXtW5cnKWrk8dQYHXkFUgasHKLgVusvAGffExw7cAo\no50EKlTkExQ+Xoj48HcWzeK/jeKXe0WvpWwJqGDPf70guGhVsHuDC2fPaHOh63uZ\nfwIDAQAB\n-----END PUBLIC KEY-----\n","pk_uid":0}'
    cipherText = rsa_encrypt(rsa_pk, plainText)
    plainText_c = rsa_decrypt(rsa_sk, cipherText)
    print(plainText_c)
    web.run_app(app, port=11151)