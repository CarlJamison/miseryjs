const struct = require('python-struct');

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

  var buf = null;
  var size = 0;

  function addshort(s) {
     size += 2;
     return struct.pack("<h", s);
  }

  function addint(i) {
    size += 4;
    return struct.pack("<i", i);
  }

  function addstr(s) {
    s += String.fromCharCode(0);

    var fmt = `<L${s.length}s`;

    size += struct.sizeOf(fmt);
    return struct.pack(fmt, s.length, s);
  }

  function addWstr(s) {
    const textEncoder = new TextEncoder("utf-16_le");
    s = textEncoder.encode(s);
    var fmt = `<L${s.length+2}s`;
    console.log(fmt)
    size += struct.sizeOf(fmt);
    return struct.pack(fmt, s.length+2, s)
  }

  function addbinary(b) {
    var fmt = `<L${b.length+1}s`;
    size += struct.sizeOf(fmt);
    return struct.pack(fmt, b.length+1, b)
  }

  var test = "test";
  console.log(`starting up! ${test}`);

  for(var i = 0; i < fstring.length; i++)
  {
    console.log(fstring[i]);
    console.log(args[i]);
    if(fstring[i] == "b")
    {
      packed = addbinary(args[i]);
    }
    else if(fstring[i] == "i")
    {
      packed = addint(args[i]);
    }
    else if(fstring[i] == "s")
    {
      packed = addshort(args[i]);
    }
    else if(fstring[i] == "z")
    {
      packed = addstr(args[i]);
    }
    else if(fstring[i] == "Z")
    {
      packed = addWstr(args[i]);
    }
    else
    {
      console.log(`Invalid character in fstring: ${fstring[i]}`);
      return [];
    }
    buf = buf ? Buffer.concat([buf, packed], buf.length+packed.length) : packed; // unreadible
  }
  return buf;
}

fstring = "ssszzz";
args = [2, 3, 4, "hello", "world", "misery"];
buf = bof_pack(fstring, args);

console.log(buf.toString('hex'));













