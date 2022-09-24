var tabTemplate = "<li><a href='#{href}'>#{label}</a> <span class='ui-icon ui-icon-close' role='presentation'>Remove Tab</span></li>";

$.getJSON("module-scripts", data => data.forEach(l => $.getScript(l)));

var types = {
  0: message => { //Echo
    terminal.echo(`[[b;white;black]${$.terminal.escape_brackets(message.output)}]`);
  },
  1: message => { //Download
    const linkSource = `data:application/octet-stream;base64,${message.output}`
    const downloadLink = document.createElement('a');
    document.body.appendChild(downloadLink);

    downloadLink.href = linkSource;
    downloadLink.target = '_self';
    downloadLink.download = currentId + Math.floor(Math.random() * 1000);
    downloadLink.click(); 
  },
  2: message => { //Image
    const str2blob = b64toBlob(message.output);
    var imageUrl = URL.createObjectURL(str2blob);
    const img = $(`<img src="${imageUrl}">`);
    terminal.echo(img);
  },
  3: message => { //PWD
    types[0](message);
  },
}

function handleEcho(message) {
  if(!message.output){
    message = {output: message, returnType: 0};
  }
  types[message.returnType](message);
}

function b64toBlob(b64Data, contentType='image/jpeg', sliceSize=512){
  const byteCharacters = atob(b64Data);
  const byteArrays = [];

  for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
      const slice = byteCharacters.slice(offset, offset + sliceSize);

      const byteNumbers = new Array(slice.length);
      for (let i = 0; i < slice.length; i++) {
          byteNumbers[i] = slice.charCodeAt(i);
      }

      const byteArray = new Uint8Array(byteNumbers);
      byteArrays.push(byteArray);
  }

  return new Blob(byteArrays, {type: contentType});
}