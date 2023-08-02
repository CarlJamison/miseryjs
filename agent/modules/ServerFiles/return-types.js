types = {
    ...types,
    12: message => {
        
        var content = `<div class=server-storage-content>${getFileHtml(message.output)}</div>`;

        var contentHandle = $(".server-storage-content");

        if(!contentHandle.length){
            createTab("Server Storage", content);
        }else{
            contentHandle.html(content)
        }

    },
}

function getFileHtml(file, out = "", indent = "") {

    var out = indent + file.name + "\n";

    if (file.children) {
        file.children.map(child =>
            out += `<div style="margin: 4px 4px 4px 20px">${getFileHtml(child, out, indent + "\t")}</div>`
        );
    }

    return out;
}

