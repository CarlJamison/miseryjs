const struct = require('python-struct');
const fs = require('fs')

module.exports = (fstring, args) => {
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
    s += String.fromCharCode(0x00);
    var fmt = `<L${s.length}s`;
    size += struct.sizeOf(fmt);
    return struct.pack(fmt, s.length, s);
  }

  function addWstr(s) {
    //const textEncoder = new TextEncoder("utf-16_le");
    s = Buffer.from(s, "utf16le")
    s += String.fromCharCode(0x00, 0x00);
    var fmt = `<L${s.length}s`;
    size += struct.sizeOf(fmt);
    return struct.pack(fmt, s.length, s);
  }

  function addbinary(b) {
    b += String.fromCharCode(0x00);
    var fmt = `<L${b.length}s`;
    size += struct.sizeOf(fmt);
    return struct.pack(fmt, b.length, b);
  }

  if(fstring.length != args.length)
  {
    console.log(`Format string length must be the same as argument length: fstring:${fstring.length}, args:${args.length}`);
    return null;
  }

  for(var i = 0; i < fstring.length; i++)
  {
    if(fstring[i] == "b")
    {
      try
      {
        binary = fs.readFileSync(args[i]);
      }
      catch
      {
        console.log(`Could not read contents of binary file: ${args[i]}`);
        return null;
      }
      packed = addbinary(binary);
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
      return null;
    }
    buf = buf ? Buffer.concat([buf, packed], buf.length+packed.length) : packed;
  }
  return Buffer.concat([struct.pack("<L", size), buf]); // Prepend length of the whole buffer
}