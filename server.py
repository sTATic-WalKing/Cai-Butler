from aiohttp import web
import asyncio
from bleak import BleakScanner
from bleak import BleakClient
import json
import time
import functools
import hashlib

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
    configs[client.address]['state'] = value[1]
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

def notify_callback(client, sender, value):
    global configs
    config = configs[client.address]
    config['type'] = value[0]
    config['state'] = value[1]
    
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

def hash_info():
    global configs
    global views
    global autos
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
    str = json.dumps([ related_configs, view_uids, auto_uids ]).replace(' ', '')
    hl = hashlib.md5()
    hl.update(str.encode('utf-8'))
    hashed = hl.hexdigest()
    return hashed

@routes.post('/ping')
async def _ping(request):
    content = {}
    content['hash'] = hash_info()
    return web.Response(body=json.dumps(content))

@routes.post('/peek')
async def _peek(request):
    content = {}
    content['state'] = scan_then_connect_state
    content['count'] = scan_then_connect_count
    content['latest'] = scan_then_connect_latest
    return web.Response(body=json.dumps(content))

@routes.post('/discover')
async def _discover(request):
    ret = await _peek(request)
    asyncio.create_task(scan_then_connect())
    return ret

@routes.post('/disconnect')
async def _disconnect(request):
    content = {}
    args = json.loads(await request.content.read())
    client = get_client(args['address'])
    if client == None:
        raise web.HTTPNotFound()
    affected = 0
    if await client.disconnect():
        affected += 1
    content["affected"] = affected
    return web.Response(body=json.dumps(content))

@routes.post('/config')
async def _config(request):
    global configs
    content = json.loads(await request.content.read())
    address = content['address']
    if address not in configs:
        raise web.HTTPNotFound()
    if len(content) > 1:
        config = configs[address]
        content['type'] = config['type']
        content['state'] = config['state']
        content['connected'] = get_client(address) != None
        configs[address] = content
    else:
        content = configs[address]
    return web.Response(body=json.dumps(content))

@routes.post('/configs')
async def _configs(request):
    global configs
    content = {}
    content['addresses'] = list(configs.keys())
    return web.Response(body=json.dumps(content))

@routes.post('/state')
async def _state(request):
    global configs
    content = {}
    args = json.loads(await request.content.read())
    address = args['address']
    client = get_client(address)
    if client == None:
        raise web.HTTPNotFound()
    if 'state' in args:
        await upload_state(client, args['state'])
    value = await client.read_gatt_char('01010101-0101-0101-0101-010101010102')
    content['state'] = value[1]
    config = configs[address]
    config['type'] = value[0]
    config['state'] = value[1]
    return web.Response(body=json.dumps(content))

@routes.post('/filter')
async def _filter(request):
    global configs
    content = {}
    content['addresses'] = []
    args = json.loads(await request.content.read())
    for address, config in configs.items():
        mark = True
        for k, v in args.items():
            if k not in config or v != config[k]:
                mark = False
                break
        if mark:
            content['addresses'].append(address)
    return web.Response(body=json.dumps(content))

@routes.post('/view')
async def _view(request):
    global views
    content = json.loads(await request.content.read())
    if 'uid' in content:
        uid = content['uid']
        if uid not in views:
            raise web.HTTPNotFound()
        view = views[uid]
        if len(content) > 1:
            content['states'] = view['states']
            views[uid] = content
        else:
            content = view
    else:
        uid = get_uid()
        content['uid'] = uid
        views[uid] = content
    return web.Response(body=json.dumps(content))

@routes.post('/views')
async def _views(request):
    global views
    content = {}
    content['uids'] = list(views.keys())
    return web.Response(body=json.dumps(content))

@routes.post('/auto')
async def _auto(request):
    global autos
    content = json.loads(await request.content.read())
    if 'uid' in content:
        uid = content['uid']
        if uid not in autos:
            raise web.HTTPNotFound()
        content = autos[uid]
    else:
        uid = get_uid()
        content['uid'] = uid
        if 'start' not in content:
            content['start'] = int(time.time())
        autos[uid] = content
        task = asyncio.create_task(handle_auto(content))
        task.add_done_callback(functools.partial(done_callback, uid))
        tasks[uid] = task
    return web.Response(body=json.dumps(content))

@routes.post('/autos')
async def _autos(request):
    global autos
    content = {}
    content['uids'] = list(autos.keys())
    return web.Response(body=json.dumps(content))

@routes.post('/abort')
async def _abort(request):
    global views
    global tasks
    global configs
    content = {}
    args = json.loads(await request.content.read())
    affected = 0
    if 'uid' in args:
        uid = args['uid']
        if uid in views:
            views.pop(uid)
            affected += 1
        if uid in tasks:
            tasks[uid].cancel()
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
    return web.Response(body=json.dumps(content))

async def on_shutdown(app):
    global clients
    while clients:
        await clients[0].disconnect()

app = web.Application()
app.on_shutdown.append(on_shutdown)
app.add_routes(routes)

if __name__ == '__main__':
    web.run_app(app, port=11151)