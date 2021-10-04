#########################################################################
# Richie Harris
# rkharris12@gmail.com
# 5/23/2021
#########################################################################

import base64, json, hashlib, hmac, math, socket, struct, sys, threading, time, urllib.parse, sha256d_fpga_sim
from pynq import Overlay, mmio

# RPC ID
USER_AGENT = "FPGAMiner"
VERSION = [0, 1]

# These control which sha256d implementation to use
SHA256D_LIBRARY_AUTO    = 'auto'
SHA256D_LIBRARY_HASHLIB = 'hashlib'
SHA256D_LIBRARY_PYTHON  = 'python'
SHA256D_LIBRARY_FPGA    = 'fpga'
SHA256D_LIBRARIES = [ SHA256D_LIBRARY_AUTO, SHA256D_LIBRARY_HASHLIB, SHA256D_LIBRARY_PYTHON, SHA256D_LIBRARY_FPGA ]

# Verbosity and log level
QUIET           = False
DEBUG           = False
DEBUG_PROTOCOL  = False
TEST            = False
LEVEL_PROTOCOL  = 'protocol'
LEVEL_INFO      = 'info'
LEVEL_DEBUG     = 'debug'
LEVEL_ERROR     = 'error'

# FPGA hasher register banks
base_addr = 0x43c00000
ctl_status_base_addr = 0x000
mid_state_base_addr = 0x400
residual_data_base_addr = 0x800
target_base_addr = 0xc00
ctl_status_mem = mmio.MMIO(base_addr + ctl_status_base_addr, 24)
mid_state_mem = mmio.MMIO(base_addr + mid_state_base_addr, 32)
residual_data_mem = mmio.MMIO(base_addr + residual_data_base_addr, 12)
target_mem = mmio.MMIO(base_addr + target_base_addr, 32)

def sha256d_python(message_bin):
    '''FPGA hashing python simulator.'''
    message = message_bin.hex() # convert to hex string
    state_init = 0x5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667 # initial state of state registers in hash function
    message_blocks = sha256d_fpga_sim.pad(message)
    # hash first 512 bit message block
    first_block = sha256d_fpga_sim.reverse_word_order(message_blocks[0:(512//4)]) # reverse word ordering for hash function
    data_in = int(first_block, 16) # convert from hex string to numerical data
    mid_state = sha256d_fpga_sim.hash(state_init, data_in)
    # hash second 512 bit message_block
    second_block = sha256d_fpga_sim.reverse_word_order(message_blocks[(512//4):(1024//4)]) # reverse word ordering for hash function
    data_in = int(second_block, 16) # convert from hex string to numerical data
    hash_1 = sha256d_fpga_sim.hash(mid_state, data_in)
    hash_1_word_rev = sha256d_fpga_sim.reverse_word_order(hex(hash_1).rstrip("L").lstrip("0x")) # put it back into big endian word order for padding function
    # hash a second time
    padded_in_2 = sha256d_fpga_sim.pad(hash_1_word_rev)
    block = sha256d_fpga_sim.reverse_word_order(padded_in_2) # reverse word ordering for hash function
    data_in = int(block, 16) # convert from hex string to numerical data
    hash_2 = sha256d_fpga_sim.hash(state_init, data_in)
    hash_2_word_rev = sha256d_fpga_sim.reverse_word_order(hex(hash_2).rstrip("L").lstrip("0x")) # put it back into big endian word order
    while len(hash_2_word_rev) < 64:
        hash_2_word_rev = hash_2_word_rev + "0"
    hash_2_result = bytes.fromhex(hash_2_word_rev) # convert to bytes which is the expected output
    return hash_2_result

def sha256d_hashlib(message):
    '''Double SHA256 Hashing function.'''
    return hashlib.sha256(hashlib.sha256(message).digest()).digest()

def log(message, level):
    '''Conditionally write a message to stdout based on command line options and level.'''
    global DEBUG
    global DEBUG_PROTOCOL
    global QUIET

    if QUIET and level != LEVEL_ERROR: return
    if not DEBUG_PROTOCOL and level == LEVEL_PROTOCOL: return
    if not DEBUG and level == LEVEL_DEBUG: return

    if level != LEVEL_PROTOCOL: message = '[%s] %s' % (level.upper(), message)

    print ("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), message))

def swap_endian_word(hex_word):
    '''Swaps the endianness of a hexidecimal string of a word and converts to bytes.'''
    message = bytes.fromhex(hex_word)
    if len(message) != 4: raise ValueError('Must be 4-byte word')
    return message[::-1]

def swap_endian_words(hex_words):
    '''Swaps the endianness of a hexidecimal string of words and converts to bytes.'''
    message = bytes.fromhex(hex_words)
    if len(message) % 4 != 0: raise ValueError('Must be 4-byte word aligned')
    return b''.join([ message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4) ])

def human_readable_hashrate(hashrate):
    '''Returns a human readable representation of hashrate.'''
    if hashrate < 1000:
        return '%2f hashes/s' % hashrate
    if hashrate < 1000000:
        return '%2f khashes/s' % (hashrate / 1000)
    if hashrate < 1000000000:
        return '%2f Mhashes/s' % (hashrate / 1000000)
    return '%2f Ghashes/s' % (hashrate / 1000000000)

SHA256D_LIBRARY = None
sha256d_proof_of_work = None
def set_sha256d_library(library = SHA256D_LIBRARY_AUTO):
    '''Sets the sha256d library implementation to use.'''
    global SHA256D_LIBRARY
    global sha256d_proof_of_work

    if library == SHA256D_LIBRARY_FPGA:
        overlay = Overlay('/home/xilinx/overlays/miner_top.bit') # Load Pynq FPGA overlay
        sha256d_proof_of_work = None
        SHA256D_LIBRARY = library

    elif library == SHA256D_LIBRARY_PYTHON:
        sha256d_proof_of_work = lambda message: sha256d_python(message)
        SHA256D_LIBRARY = library
  
    else:
        sha256d_proof_of_work = lambda message: sha256d_hashlib(message)
        SHA256D_LIBRARY = SHA256D_LIBRARY_HASHLIB

class Job(object):
    '''Encapsulates a Job from the network and necessary helper methods to mine.

        "If you have a procedure with 10 parameters, you probably missed some."
           ~Alan Perlis
    '''
    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, target, extranonce1, extranonce2_size, proof_of_work):
        # Job parts from the mining.notify command
        self._job_id = job_id
        self._prevhash = prevhash
        self._coinb1 = coinb1
        self._coinb2 = coinb2
        self._merkle_branches = [ b for b in merkle_branches ]
        self._version = version
        self._nbits = nbits
        self._ntime = ntime
        # Job information needed to mine from mining.subsribe
        self._target = target
        self._extranonce1 = extranonce1
        self._extranonce2_size = extranonce2_size
        # Proof of work algorithm
        self._proof_of_work = proof_of_work
        # Flag to stop this job's mine coroutine
        self._done = False
        # Hash metrics (start time, delta time, total hashes)
        self._dt = 0.0
        self._hash_count = 0

    # Accessors
    id = property(lambda s: s._job_id)
    prevhash = property(lambda s: s._prevhash)
    coinb1 = property(lambda s: s._coinb1)
    coinb2 = property(lambda s: s._coinb2)
    merkle_branches = property(lambda s: [ b for b in s._merkle_branches ])
    version = property(lambda s: s._version)
    nbits = property(lambda s: s._nbits)
    ntime = property(lambda s: s._ntime)

    target = property(lambda s: s._target)
    extranonce1 = property(lambda s: s._extranonce1)
    extranonce2_size = property(lambda s: s._extranonce2_size)

    proof_of_work = property(lambda s: s._proof_of_work)

    @property
    def hashrate(self):
        '''The current hashrate, or if stopped hashrate for the job's lifetime.'''
        if self._dt == 0: return 0.0
        return self._hash_count / self._dt

    def merkle_root_bin(self, extranonce2_bin):
        '''Builds a merkle root from the merkle tree'''
        coinbase_bin = bytes.fromhex(self._coinb1) + bytes.fromhex(self._extranonce1) + extranonce2_bin + bytes.fromhex(self._coinb2)
        coinbase_hash_bin = sha256d_hashlib(coinbase_bin)

        merkle_root = coinbase_hash_bin
        for branch in self._merkle_branches:
            merkle_root = sha256d_hashlib(merkle_root + bytes.fromhex(branch))
        return merkle_root

    def stop(self):
        '''Requests the mine coroutine stop after its current iteration.'''
        self._done = True

    def mine(self, nonce_start = 0, nonce_stride = 1):
        '''Returns an iterator that iterates over valid proof-of-work shares.

        This is a co-routine; that takes a LONG time; the calling thread should look like:

        for result in job.mine(self):
           submit_work(result)

       nonce_start and nonce_stride are useful for multi-processing if you would like
       to assign each process a different starting nonce (0, 1, 2, ...) and a stride
       equal to the number of processes.
        '''
        t0 = time.time()

        # @TODO: test for extranonce != 0... Do I reverse it or not?
        for extranonce2 in range(0, 0x7fffffff):

            # Must be unique for any given job id, according to http://mining.bitcoin.cz/stratum-mining/ but never seems enforced?
            extranonce2_bin = struct.pack('<I', extranonce2)

            merkle_root_bin = self.merkle_root_bin(extranonce2_bin)
            header_prefix_bin = swap_endian_word(self._version) + swap_endian_words(self._prevhash) + merkle_root_bin + swap_endian_word(self._ntime) + swap_endian_word(self._nbits)

            if SHA256D_LIBRARY == SHA256D_LIBRARY_FPGA:
                header_prefix = header_prefix_bin.hex() # convert to hex string
                # do the first hash that is independent of the nonce
                state_init = 0x5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667 # initial state of state registers in hash function
                first_block = sha256d_fpga_sim.reverse_word_order(header_prefix[0:(512//4)])
                data_in = int(first_block, 16)
                mid_state = sha256d_fpga_sim.hash(state_init, data_in)
                residual_data = int(sha256d_fpga_sim.reverse_word_order(header_prefix[-24:]), 16)
                target = int(self.target, 16) # convert target to int
            
                # write the FPGA registers to configure and start the hasher
                for offset in list(range(8)): # set mid_state
                    mid_state_mem.write(4*offset, sha256d_fpga_sim.idx(mid_state, offset))
                for offset in list(range(3)): # set residual_data
                    residual_data_mem.write(4*offset, sha256d_fpga_sim.idx(residual_data, offset))
                for offset in list(range(8)): # set target
                    target_mem.write(4*offset, sha256d_fpga_sim.idx(target, offset))
                ctl_status_mem.write(0x4, 0x1) # start the hasher
                # wait for hasher to find the nonce or request new data to hash
                fpga_result = "none"
                while (True):
                    # This job has been asked to stop
                    if self._done:
                        ctl_status_mem.write(0x10, 0x1)
                        num_hashes = ctl_status_mem.read(0x14)
                        ctl_status_mem.write(0x0, 0x1)
                        self._hash_count += num_hashes
                        self._dt += (time.time() - t0)
                        raise StopIteration()
                    status = ctl_status_mem.read(0x8)
                    if (status == 1):
                        fpga_result = ctl_status_mem.read(0xc)
                        break
                    elif (status == 2):
                        break

                # if nonce was found, submit result
                if fpga_result != "none":
                    nonce_bin = struct.pack('<I', fpga_result)

                    result = dict(
                        job_id = self.id,
                        extranonce2 = extranonce2_bin.hex(),
                        ntime = str(self._ntime), # Convert to str from json unicode
                        nonce = nonce_bin[::-1].hex()
                    )
                    self._dt += (time.time() - t0)
                    self._hash_count += fpga_result

                    yield result

                    t0 = time.time()
                else:
                    self._hash_count += 2**32
            else:
                for nonce in range(nonce_start, 0xffffffff, nonce_stride):
                    # This job has been asked to stop
                    if self._done:
                        self._dt += (time.time() - t0)
                        raise StopIteration()

                    # Proof-of-work attempt
                    nonce_bin = struct.pack('<I', nonce)

                    pow = self.proof_of_work(header_prefix_bin + nonce_bin)[::-1].hex()

                    # Did we reach or exceed our target?
                    if pow <= self.target:
                        result = dict(
                            job_id = self.id,
                            extranonce2 = extranonce2_bin.hex(),
                            ntime = str(self._ntime), # Convert to str from json unicode
                            nonce = nonce_bin[::-1].hex()
                        )
                        self._dt += (time.time() - t0)

                        yield result

                        t0 = time.time()

                    self._hash_count += 1

    def __str__(self):
        return '<Job id=%s prevhash=%s coinb1=%s coinb2=%s merkle_branches=%s version=%s nbits=%s ntime=%s target=%s extranonce1=%s extranonce2_size=%d>' % (self.id, self.prevhash, self.coinb1, self.coinb2, self.merkle_branches, self.version, self.nbits, self.ntime, self.target, self.extranonce1, self.extranonce2_size)

# Subscription state
class Subscription(object):
    '''Encapsulates the Subscription state from the JSON-RPC server'''

    # Subclasses should override this
    def ProofOfWork(header):
        raise Exception('Do not use the Subscription class directly, subclass it')

    class StateException(Exception): pass

    def __init__(self):
        self._id = None
        self._difficulty = None
        self._extranonce1 = None
        self._extranonce2_size = None
        self._target = None
        self._worker_name = None
        self._mining_thread = None

    # Accessors
    id = property(lambda s: s._id)
    worker_name = property(lambda s: s._worker_name)

    difficulty = property(lambda s: s._difficulty)
    target = property(lambda s: s._target)

    extranonce1 = property(lambda s: s._extranonce1)
    extranonce2_size = property(lambda s: s._extranonce2_size)

    def set_worker_name(self, worker_name):
        if self._worker_name:
            raise self.StateException('Already authenticated as %r (requesting %r)' % (self._username, username))
        
        self._worker_name = worker_name

    def _set_target(self, target):
        self._target = '%064x' % target

    def set_difficulty(self, difficulty):
        if difficulty < 0: raise self.StateException('Difficulty must be non-negative')

        # Compute target
        if difficulty == 0:
            target = 2 ** 256 - 1
        else:
            target = min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

        self._difficulty = difficulty
        self._set_target(target)

    def set_subscription(self, subscription_id, extranonce1, extranonce2_size):
        if self._id is not None:
            raise self.StateException('Already subscribed')

        self._id = subscription_id
        self._extranonce1 = extranonce1
        self._extranonce2_size = extranonce2_size

    def create_job(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        '''Creates a new Job object populated with all the goodness it needs to mine.'''
        if self._id is None:
            raise self.StateException('Not subscribed')

        return Job(
            job_id = job_id,
            prevhash = prevhash,
            coinb1 = coinb1,
            coinb2 = coinb2,
            merkle_branches = merkle_branches,
            version = version,
            nbits = nbits,
            ntime = ntime,
            target = self.target,
            extranonce1 = self._extranonce1,
            extranonce2_size = self.extranonce2_size,
            proof_of_work = self.ProofOfWork
        )

    def __str__(self):
        return '<Subscription id=%s, extranonce1=%s, extranonce2_size=%d, difficulty=%d worker_name=%s>' % (self.id, self.extranonce1, self.extranonce2_size, self.difficulty, self.worker_name)

class SubscriptionSHA256D(Subscription):
    '''Subscription for Double-SHA256-based coins, like Bitcoin.'''
    ProofOfWork = lambda s, m: (sha256d_proof_of_work(m))

class SimpleJsonRpcClient(object):
    '''Simple JSON-RPC client.

    To use this class:
        1) Create a sub-class
        2) Override handle_reply(self, request, reply)
        3) Call connect(socket)

    Use self.send(method, params) to send JSON-RPC commands to the server.

    A new thread is created for listening to the connection; so calls to handle_reply
    are synchronized. It is safe to call send from withing handle_reply.
    '''

    class ClientException(Exception): pass

    class RequestReplyException(Exception):
        def __init__(self, message, reply, request = None):
            Exception.__init__(self, message)
            self._reply = reply
            self._request = request

        request = property(lambda s: s._request)
        reply = property(lambda s: s._reply)

    class RequestReplyWarning(RequestReplyException):
        '''Sub-classes can raise this to inform the user of JSON-RPC server issues.'''
        pass

    def __init__(self):
        self._socket = None
        self._lock = threading.RLock()
        self._rpc_thread = None
        self._message_id = 1
        self._requests = dict()


    def _handle_incoming_rpc(self):
        data = ""
        while True:
            # Get the next line if we have one, otherwise, read and block
            if '\n' in data:
                (line, data) = data.split('\n', 1)
            else:
                chunk = self._socket.recv(1024).decode()
                data += chunk
                continue

            log('JSON-RPC Server > ' + line, LEVEL_PROTOCOL)

            # Parse the JSON
            try:
                reply = json.loads(line)
            except Exception as e:
                log("JSON-RPC Error: Failed to parse JSON %r (skipping)" % line, LEVEL_ERROR)
                continue

            try:
                request = None
                with self._lock:
                    if 'id' in reply and reply['id'] in self._requests:
                        request = self._requests[reply['id']]
                    self.handle_reply(request = request, reply = reply)
            except self.RequestReplyWarning as e:
                output = e.message
                if e.request:
                    output += '\n  ' + e.request
                output += '\n  ' + e.reply
                log(output, LEVEL_ERROR)

    def handle_reply(self, request, reply):
        # Override this method in sub-classes to handle a message from the server
        raise self.RequestReplyWarning('Override this method')

    def send(self, method, params):
        '''Sends a message to the JSON-RPC server'''
        if not self._socket:
            raise self.ClientException('Not connected')

        request = dict(id = self._message_id, method = method, params = params)
        message = json.dumps(request)
        message += '\n'
        with self._lock:
            self._requests[self._message_id] = request
            self._message_id += 1
            self._socket.send(message.encode())

        log('JSON-RPC Server < ' + message, LEVEL_PROTOCOL)

        return request

    def connect(self, socket):
        '''Connects to a remove JSON-RPC server'''
        if self._rpc_thread:
            raise self.ClientException('Already connected')

        self._socket = socket
        self._rpc_thread = threading.Thread(target = self._handle_incoming_rpc)
        self._rpc_thread.daemon = True
        self._rpc_thread.start()

# Miner client
class Miner(SimpleJsonRpcClient):
    '''Simple mining client'''

    class MinerWarning(SimpleJsonRpcClient.RequestReplyWarning):
        def __init__(self, message, reply, request = None):
            SimpleJsonRpcClient.RequestReplyWarning.__init__(self, 'Mining Sate Error: ' + message, reply, request)

    class MinerAuthenticationException(SimpleJsonRpcClient.RequestReplyException): pass

    def __init__(self, url, username, password):
        SimpleJsonRpcClient.__init__(self)

        self._url = url
        self._username = username
        self._password = password

        self._subscription = SubscriptionSHA256D()

        self._job = None

        self._accepted_shares = 0

    # Accessors
    url = property(lambda s: s._url)
    username = property(lambda s: s._username)
    password = property(lambda s: s._password)

    # Overridden from SimpleJsonRpcClient
    def handle_reply(self, request, reply):

        # New work, stop what we were doing before, and start on this.
        if reply.get('method') == 'mining.notify':
            if 'params' not in reply or len(reply['params']) != 9:
                raise self.MinerWarning('Malformed mining.notify message', reply)

            (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
            self._spawn_job_thread(job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime)

            log('New job: job_id=%s' % job_id, LEVEL_DEBUG)

        # The server wants us to change our difficulty (on all *future* work)
        elif reply.get('method') == 'mining.set_difficulty':
            if 'params' not in reply or len(reply['params']) != 1:
                raise self.MinerWarning('Malformed mining.set_difficulty message', reply)

            (difficulty, ) = reply['params']
            self._subscription.set_difficulty(difficulty)

            log('Change difficulty: difficulty=%s' % difficulty, LEVEL_DEBUG)

        # This is a reply to...
        elif request:

            # ...subscribe; set-up the work and request authorization
            if request.get('method') == 'mining.subscribe':
                if 'result' not in reply or len(reply['result']) != 3 or len(reply['result'][0]) != 2:
                    raise self.MinerWarning('Reply to mining.subscribe is malformed', reply, request)

                ((mining_notify, subscription_id), extranonce1, extranonce2_size) = reply['result']

                self._subscription.set_subscription(subscription_id, extranonce1, extranonce2_size)

                log('Subscribed: subscription_id=%s' % subscription_id, LEVEL_DEBUG)

                # Request authentication
                self.send(method = 'mining.authorize', params = [ self.username, self.password ])

            # ...authorize; if we failed to authorize, quit
            elif request.get('method') == 'mining.authorize':
                if 'result' not in reply or not reply['result']:
                    raise self.MinerAuthenticationException('Failed to authenticate worker', reply, request)

                worker_name = request['params'][0]
                self._subscription.set_worker_name(worker_name)

                log('Authorized: worker_name=%s' % worker_name, LEVEL_DEBUG)

            # ...submit; complain if the server didn't accept our submission
            elif request.get('method') == 'mining.submit':
                if 'result' not in reply or not reply['result']:
                    log('Share - Invalid', LEVEL_INFO)
                    raise self.MinerWarning('Failed to accept submit', reply, request)

                self._accepted_shares += 1
                log('Accepted shares: %d' % self._accepted_shares, LEVEL_INFO)

            # ??? *shrug*
            else:
                raise self.MinerWarning('Unhandled message', reply, request)

        # ??? *double shrug*
        else:
            raise self.MinerWarning('Bad message state', reply)

    def _spawn_job_thread(self, job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime):
        '''Stops any previous job and begins a new job.'''
        # Stop the old job (if any)
        if self._job: self._job.stop()

        # Create the new job
        self._job = self._subscription.create_job(
            job_id = job_id,
            prevhash = prevhash,
            coinb1 = coinb1,
            coinb2 = coinb2,
            merkle_branches = merkle_branches,
            version = version,
            nbits = nbits,
            ntime = ntime
        )

        def run(job):
            try:
                for result in job.mine():
                    params = [ self._subscription.worker_name ] + [ result[k] for k in ('job_id', 'extranonce2', 'ntime', 'nonce') ]
                    self.send(method = 'mining.submit', params = params)
                    log("Found share: " + str(params), LEVEL_INFO)
                log("Hashrate: %s" % human_readable_hashrate(job.hashrate), LEVEL_INFO)
            except Exception as e:
                log("ERROR: %s" % e, LEVEL_ERROR)

        thread = threading.Thread(target = run, args = (self._job, ))
        thread.daemon = True
        thread.start()

    def serve_forever(self):
        '''Begins the miner. This method does not return.'''
        # Figure out the hostname and port
        url = urllib.parse.urlparse(self.url)
        hostname = url.hostname or ''
        port = url.port or 9333

        log('Starting server on %s:%d' % (hostname, port), LEVEL_INFO)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        self.connect(sock)

        self.send(method = 'mining.subscribe', params = [ "%s/%s" % (USER_AGENT, '.'.join(str(p) for p in VERSION)) ])

        # Forever...
        while True:
            time.sleep(10)

def test_subscription(library):
    '''Test harness for mining, using a known valid share.'''
  
    log('TEST: Sha256d implementation = %r' % library, LEVEL_INFO)
    time.sleep(2)
    log('TEST: Testing Subscription', LEVEL_DEBUG)

    subscription = SubscriptionSHA256D()

    # Set up the subscription
    reply = json.loads('{"id":1,"result":[[["mining.set_difficulty","1"],["mining.notify","1"]],"",8],"error":null}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    ((mining_notify, subscription_id), extranonce1, extranonce2_size) = reply['result']
    subscription.set_subscription(subscription_id, extranonce1, extranonce2_size)

    # Set the difficulty
    reply = json.loads('{"id":null,"method":"mining.set_difficulty","params":[32768]}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    (difficulty, ) = reply['params']
    subscription.set_difficulty(difficulty)

    # Create a job
    reply = json.loads('{"id":null,"method":"mining.notify","params":["1d987a1338","3ac400955224c625ad00510bf9b92cf824fd72dabc96a44700000b6000000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704b3936a1a017cffffffff01403d522a01000000434104563053b8900762f3d3e8725012d617d177e3c4af3275c3265a1908b434e0df91ec75603d0d8955ef040e5f68d5c36989efe21a59f4ef94a5cc95c99794a84492ac","",["b4839c227eb12a4682ef507024a44066d1b54b2a224cf4765bdd46b35a42d0e3", "ff55ad590268952712d3586af4f4619eb5f280ed671e2a7dca766076994e19ff", "d8adfb1856bc923a6da4e83914013405334915d4ece1eb36d09cef8119850ea4", "ce28b22ba91639d5ae35d0f7a17e02b422fa251c372cb600daf62b7f3df0bdbd"],"00000001","1a6a93b3","4dcbc8a6",true]}')
    log('TEST: %r' % reply, LEVEL_DEBUG)
    (job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs) = reply['params']
    job = subscription.create_job(
        job_id = job_id,
        prevhash = prevhash,
        coinb1 = coinb1,
        coinb2 = coinb2,
        merkle_branches = merkle_branches,
        version = version,
        nbits = nbits,
        ntime = ntime
    )

    # Scan that job (if I broke something, this will run for a long time))
    for result in job.mine(nonce_start = 2436437219 - 5):
        log('TEST: found share - %r' % repr(result), LEVEL_INFO)
        break

    valid = { 'ntime': '4dcbc8a6', 'nonce': '913914e3', 'extranonce2': '00000000', 'job_id': u'1d987a1338' }
    log('TEST: Correct answer %r' % valid, LEVEL_INFO)
    time.sleep(2)


# CLI for mining
if __name__ == '__main__':
    import argparse

    # Parse the command line
    parser = argparse.ArgumentParser(description = "CPU and FPGA Bitcoin miner using the stratum protocol")

    parser.add_argument('-o', '--url', help = 'stratum mining server url (eg: stratum+tcp://foobar.com:3333)')
    parser.add_argument('-u', '--user', dest = 'username', default = '', help = 'username for mining server', metavar = "USERNAME")
    parser.add_argument('-p', '--pass', dest = 'password', default = '', help = 'password for mining server', metavar = "PASSWORD")

    parser.add_argument('-O', '--userpass', help = 'username:password pair for mining server', metavar = "USERNAME:PASSWORD")

    parser.add_argument('-i', '--impl', default = SHA256D_LIBRARY_AUTO, choices = list(set(SHA256D_LIBRARIES)), help = 'library implementation for sha256d')

    parser.add_argument('-B', '--background', action ='store_true', help = 'run in the background as a daemon')

    parser.add_argument('-q', '--quiet', action ='store_true', help = 'suppress non-errors')
    parser.add_argument('-P', '--dump-protocol', dest = 'protocol', action ='store_true', help = 'show all JSON-RPC chatter')
    parser.add_argument('-d', '--debug', action ='store_true', help = 'show extra debug information')
    parser.add_argument('-t', '--test', action ='store_true', help = 'run offline test harness with all implementations')

    parser.add_argument('-v', '--version', action = 'version', version = '%s/%s' % (USER_AGENT, '.'.join(str(v) for v in VERSION)))

    options = parser.parse_args(sys.argv[1:])

    message = None

    # Get the username/password
    username = options.username
    password = options.password

    if options.userpass:
        if username or password:
            message = 'May not use -O/-userpass in conjunction with -u/--user or -p/--pass'
        else:
            try:
                (username, password) = options.userpass.split(':')
            except Exception as e:
                message = 'Could not parse username:password for -O/--userpass'

    # Was there an issue? Show the help screen and exit.
    if message:
        parser.print_help()
        print("")
        print(message)
        sys.exit(1)

    # Set the logging level
    if options.debug: DEBUG = True
    if options.protocol: DEBUG_PROTOCOL = True
    if options.quiet: QUIET = True
    if options.test: TEST = True

    # Set the library implementation
    if options.impl:
        if options.impl not in SHA256D_LIBRARIES:
            parser.print_help()
            print("")
            print('Implementation not available for sha256d')
            sys.exit(1)
        else:
            set_sha256d_library(options.impl)
    else:
        set_sha256d_library(SHA256D_LIBRARY_AUTO)
    log('Using sha256d library %r' % SHA256D_LIBRARY, LEVEL_DEBUG)

    if TEST:
        for library in SHA256D_LIBRARIES:
            set_sha256d_library(library)
            test_subscription(library)
    else:
        # They want a daemon, give them a daemon
        if options.background:
            import os
            if os.fork() or os.fork(): sys.exit()
    
        # Heigh-ho, heigh-ho, it's off to work we go...
        if options.url:
            miner = Miner(options.url, username, password)
            miner.serve_forever()
