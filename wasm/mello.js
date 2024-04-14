

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
};

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}

const CsrfKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_csrfkey_free(ptr >>> 0));
/**
* Private key used to sign and verify tokens.
*/
export class CsrfKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CsrfKey.prototype);
        obj.__wbg_ptr = ptr;
        CsrfKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CsrfKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_csrfkey_free(ptr);
    }
    /**
    * Generate a new random key.
    * @returns {CsrfKey}
    */
    static generate() {
        const ret = wasm.csrfkey_generate();
        return CsrfKey.__wrap(ret);
    }
    /**
    * Derive a new key, keys with the same tag are equals.
    * @param {string} tag
    * @returns {CsrfKey}
    */
    derive(tag) {
        const ptr0 = passStringToWasm0(tag, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.csrfkey_derive(this.__wbg_ptr, ptr0, len0);
        return CsrfKey.__wrap(ret);
    }
    /**
    * Returns a string representing this object.
    * @returns {string}
    */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.csrfkey_toString(retptr, this.__wbg_ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Parses a string containing a CSRF key.
    * @param {string} s
    * @returns {CsrfKey}
    */
    static parseFromString(s) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.csrfkey_parseFromString(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CsrfKey.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}

const CsrfTokenFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_csrftoken_free(ptr >>> 0));
/**
* CSRF signed token.
*/
export class CsrfToken {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CsrfToken.prototype);
        obj.__wbg_ptr = ptr;
        CsrfTokenFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CsrfTokenFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_csrftoken_free(ptr);
    }
    /**
    * Generate a new CSRF random token, signed with the given key.
    * @param {CsrfKey} key
    * @returns {CsrfToken}
    */
    static generate(key) {
        _assertClass(key, CsrfKey);
        const ret = wasm.csrftoken_generate(key.__wbg_ptr);
        return CsrfToken.__wrap(ret);
    }
    /**
    * Verify the CSRF token with the given key.
    * @param {CsrfKey} key
    */
    verify(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, CsrfKey);
            wasm.csrftoken_verify(retptr, this.__wbg_ptr, key.__wbg_ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
    * Returns a string representing this object.
    * @returns {string}
    */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.csrftoken_toString(retptr, this.__wbg_ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
    * Parses a string containing a CSRF token.
    * @param {string} s
    * @returns {CsrfToken}
    */
    static parseFromString(s) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.csrftoken_parseFromString(retptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return CsrfToken.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}

const imports = {
    __wbindgen_placeholder__: {
        __wbindgen_error_new: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
        __wbg_crypto_566d7465cdbb6b7a: function(arg0) {
            const ret = getObject(arg0).crypto;
            return addHeapObject(ret);
        },
        __wbindgen_is_object: function(arg0) {
            const val = getObject(arg0);
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg_process_dc09a8c7d59982f6: function(arg0) {
            const ret = getObject(arg0).process;
            return addHeapObject(ret);
        },
        __wbg_versions_d98c6400c6ca2bd8: function(arg0) {
            const ret = getObject(arg0).versions;
            return addHeapObject(ret);
        },
        __wbg_node_caaf83d002149bd5: function(arg0) {
            const ret = getObject(arg0).node;
            return addHeapObject(ret);
        },
        __wbindgen_is_string: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'string';
            return ret;
        },
        __wbg_msCrypto_0b84745e9245cdf6: function(arg0) {
            const ret = getObject(arg0).msCrypto;
            return addHeapObject(ret);
        },
        __wbg_require_94a9da52636aacbf: function() { return handleError(function () {
            const ret = module.require;
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_is_function: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbindgen_string_new: function(arg0, arg1) {
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbg_randomFillSync_290977693942bf03: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).randomFillSync(takeObject(arg1));
        }, arguments) },
        __wbg_getRandomValues_260cc23a41afad9a: function() { return handleError(function (arg0, arg1) {
            getObject(arg0).getRandomValues(getObject(arg1));
        }, arguments) },
        __wbg_newnoargs_e258087cd0daa0ea: function(arg0, arg1) {
            const ret = new Function(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_call_27c0f87801dedf93: function() { return handleError(function (arg0, arg1) {
            const ret = getObject(arg0).call(getObject(arg1));
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbg_self_ce0dbfc45cf2f5be: function() { return handleError(function () {
            const ret = self.self;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_window_c6fb939a7f436783: function() { return handleError(function () {
            const ret = window.window;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_globalThis_d1e6af4856ba331b: function() { return handleError(function () {
            const ret = globalThis.globalThis;
            return addHeapObject(ret);
        }, arguments) },
        __wbg_global_207b558942527489: function() { return handleError(function () {
            const ret = global.global;
            return addHeapObject(ret);
        }, arguments) },
        __wbindgen_is_undefined: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg_call_b3ca7c6051f9bec1: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments) },
        __wbg_buffer_12d079cc21e14bdb: function(arg0) {
            const ret = getObject(arg0).buffer;
            return addHeapObject(ret);
        },
        __wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb: function(arg0, arg1, arg2) {
            const ret = new Uint8Array(getObject(arg0), arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_new_63b92bc8671ed464: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_set_a47bac70306a19a7: function(arg0, arg1, arg2) {
            getObject(arg0).set(getObject(arg1), arg2 >>> 0);
        },
        __wbg_newwithlength_e9b4878cebadb3d3: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return addHeapObject(ret);
        },
        __wbg_subarray_a1f73cd4b5b42fe1: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
            return addHeapObject(ret);
        },
        __wbindgen_throw: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbindgen_memory: function() {
            const ret = wasm.memory;
            return addHeapObject(ret);
        },
    },

};

const wasm_url = new URL('mello_bg.wasm', import.meta.url);
let wasmCode = '';
switch (wasm_url.protocol) {
    case 'file:':
    wasmCode = await Deno.readFile(wasm_url);
    break
    case 'https:':
    case 'http:':
    wasmCode = await (await fetch(wasm_url)).arrayBuffer();
    break
    default:
    throw new Error(`Unsupported protocol: ${wasm_url.protocol}`);
}

const wasmInstance = (await WebAssembly.instantiate(wasmCode, imports)).instance;
const wasm = wasmInstance.exports;

