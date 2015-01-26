    var LL = Module;
    
    var getbuf = function (ptr, length) {
        if (length === 0 || !ptr) return '';
        var ret = '';
        var MAX_CHUNK = 1024; // split up into chunks, because .apply on a huge string can overflow the stack
        var curr;
        while (length > 0) {
            curr = String.fromCharCode.apply(
                String, HEAPU8.subarray(ptr, ptr + Math.min(length, MAX_CHUNK)));
            ret = ret ? ret + curr : curr;
            ptr += MAX_CHUNK;
            length -= MAX_CHUNK;
        }
        return ret;
    }
    
    
    var create_seed = function(){
        var seed = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var res = _ed25519_create_seed(seed);
        if(res != 0) return;
        return getbuf(seed,  32);
    };

    var create_keypair = function(seed){
        var seedptr = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        if(seed) {
            if(seed.length != 32) throw new Error;
            LL.writeStringToMemory(seed, seedptr, true);
        } else {
            if(_ed25519_create_seed(seed) != 0) return;
        }
        var pubkey  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var privkey = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        _ed25519_create_keypair(pubkey, privkey, seedptr);
        return {
            pub:  getbuf(pubkey,  32),
            priv: getbuf(privkey, 64)
        };
    };

    var sign = function(message, pubkey, privkey){
        if(pubkey.length != 32 || privkey.length != 64) throw new Error;
        var signptr    = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        var pubkeyptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var privkeyptr = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        var msgptr     = LL.allocate(message.length, 'i8', LL.ALLOC_STACK);
        LL.writeStringToMemory(message, msgptr, true);
        LL.writeStringToMemory(pubkey, pubkeyptr, true);
        LL.writeStringToMemory(privkey, privkeyptr, true);
        _ed25519_sign(signptr, msgptr, message.length, pubkeyptr, privkeyptr);
        return getbuf(signptr, 64);
    };

    var verify = function(signature, message, pubkey){
        if(pubkey.length != 32 || signature.length != 64) throw new Error;
        var signptr    = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        var pubkeyptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var msgptr     = LL.allocate(message.length, 'i8', LL.ALLOC_STACK);
        LL.writeStringToMemory(signature, signptr, true);
        LL.writeStringToMemory(message, msgptr, true);
        LL.writeStringToMemory(pubkey, pubkeyptr, true);
        return _ed25519_verify(signptr, msgptr, message.length, pubkeyptr) == 1;
    };

    var add_scalar = function(pubkey, privkey, scalar){
        if(pubkey.length != 32 || privkey.length != 64 || scalar.length != 32) throw new Error;
        var pubkeyptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var privkeyptr = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        var scalarptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        if(pubkey)  LL.writeStringToMemory(pubkey, pubkeyptr, true);
        else        pubkeyptr = null;
        if(privkey) LL.writeStringToMemory(privkey, privkeyptr, true);
        else        privkeyptr = null;
        LL.writeStringToMemory(scalar, scalarptr, true);
        _ed25519_add_scalar(pubkeyptr, privkeyptr, scalarptr);
        return {
            pub:  getbuf(pubkeyptr,  32),
            priv: getbuf(privkeyptr, 64)
        };
    };

    var exchange_keypair = function(pubkey, privkey){
        if(pubkey.length != 32 || privkey.length != 64) throw new Error;
        var pubkeyptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        var privkeyptr = LL.allocate(64, 'i8', LL.ALLOC_STACK);
        var secretptr  = LL.allocate(32, 'i8', LL.ALLOC_STACK);
        LL.writeStringToMemory(pubkey, pubkeyptr, true);
        LL.writeStringToMemory(privkey, privkeyptr, true);
        _ed25519_keypair(secretptr, pubkeyptr, privkeyptr);
        return getbuf(secretptr,  32); 
    };

    Module.create_seed = create_seed;
    Module.create_keypair = create_keypair;
    Module.sign = sign;
    Module.verify = verify;
    Module.add_scalar = add_scalar;
    Module.exchange_keypair = exchange_keypair;
    
    window.Ed25519 = Module;
})();