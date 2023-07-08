const struct = require('struct');

function bof_pack(fstring, args) {
  // Most code taken from: https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
  // Emulates the native Cobalt Strike bof_pack() function.
  // Documented here: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#bof_pack
  //
  // Type      Description                             Unpack With (C)
  // --------|---------------------------------------|------------------------------
  // b       | binary data                           | BeaconDataExtract
  // i       | 4-byte integer                        | BeaconDataInt
  // s       | 2-byte short integer                  | BeaconDataShort
  // z       | zero-terminated+encoded string        | BeaconDataExtract
  // Z       | zero-terminated wide-char string      | (wchar_t *)BeaconDataExtract

   buffer = [];
   length = 0;

  function addshort(s) {

  }

  function addint(i) {

  }

  function addstr(s) {

  }

  function addWstr(s) {

  }

  function addbinary(b) {

  }

  var test = "test";
  console.log(`starting up! ${test}`);

  args.forEach(e => {
    console.log(e);
  });

}

fstring = "iii";
args = [2, 3, 4];
bof_pack(fstring, args);


var test = struct.Struct().doublele('length').charsnt('dir',3).word8('recurse');

var proxy = test.fields;
test.length = 14;
test.dir = 'C:\\';
test.recurse = 0;

test.allocate();

var buf = test.buffer();

console.log(buf);













